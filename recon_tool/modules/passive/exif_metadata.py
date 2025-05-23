"""
EXIF Metadata Module - Extract metadata from images (local files or URLs).
Analyzes metadata for potential security and privacy implications.
"""
import requests
import logging
import io # For handling image data in memory
import os
import re
from typing import Dict, List, Any, Optional, Union, Tuple # Added Tuple
from urllib.parse import urlparse
from datetime import datetime # For handling datetime objects in EXIF

# Try to import PIL (Pillow) for EXIF extraction
try:
    from PIL import Image # type: ignore
    from PIL.ExifTags import TAGS, GPSTAGS # type: ignore
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    # Define dummy TAGS and GPSTAGS if Pillow is not installed for type checking
    TAGS: Dict[int, str] = {}
    GPSTAGS: Dict[int, str] = {}


from ...config import DEFAULT_USER_AGENT, DEFAULT_TIMEOUT # UPDATED: Relative import
from ...utils.validators import is_valid_url # UPDATED: Relative import

logger = logging.getLogger(__name__)

def _convert_gps_to_decimal(dms_tuple: Tuple[Any, ...], ref: str) -> Optional[float]:
    """
    Convert GPS coordinates from DMS (Degrees, Minutes, Seconds) tuple to decimal degrees.
    Handles both float and Rational number inputs from Pillow.
    """
    try:
        # Pillow's Exif data can store GPS coordinates as tuples of Rational objects or floats.
        # A Rational object has num and den attributes.
        degrees = float(dms_tuple[0].num) / float(dms_tuple[0].den) if hasattr(dms_tuple[0], 'num') else float(dms_tuple[0])
        minutes = float(dms_tuple[1].num) / float(dms_tuple[1].den) if hasattr(dms_tuple[1], 'num') else float(dms_tuple[1])
        seconds = float(dms_tuple[2].num) / float(dms_tuple[2].den) if hasattr(dms_tuple[2], 'num') else float(dms_tuple[2])

        decimal_degrees = degrees + (minutes / 60.0) + (seconds / 3600.0)
        
        if ref in ['S', 'W']: # South or West implies negative
            decimal_degrees = -decimal_degrees
        return decimal_degrees
    except (TypeError, IndexError, AttributeError, ZeroDivisionError) as e:
        logger.warning(f"Could not convert GPS DMS {dms_tuple} with ref {ref} to decimal: {e}")
        return None


def _extract_metadata_from_image_obj(image_obj: Image.Image) -> Dict[str, Any]:
    """Helper function to extract metadata from an already opened Pillow Image object."""
    metadata_result: Dict[str, Any] = { # Renamed and type hinted
        "basic_info": {
            "format": image_obj.format,
            "mode": image_obj.mode,
            "width": image_obj.width,
            "height": image_obj.height,
            "image_size_pixels": f"{image_obj.width}x{image_obj.height}",
            "info": dict(image_obj.info), # Other info dict from image
        },
        "exif_data": {},
        "gps_info": {},
        "has_exif": False,
        "has_gps": False
    }

    try:
        # Pillow's _getexif() can return None if no EXIF data
        raw_exif = image_obj._getexif() # type: ignore # It's a protected member but standard way to get EXIF
        if raw_exif:
            metadata_result["has_exif"] = True
            for tag_id, value in raw_exif.items():
                tag_name = TAGS.get(tag_id, tag_id) # Get human-readable tag name
                
                # Special handling for GPSInfo
                if tag_name == "GPSInfo":
                    metadata_result["has_gps"] = True
                    for gps_tag_id, gps_value in value.items():
                        gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        metadata_result["gps_info"][gps_tag_name] = gps_value
                    
                    # Attempt to convert to decimal coordinates
                    lat_dms = metadata_result["gps_info"].get('GPSLatitude')
                    lat_ref = metadata_result["gps_info"].get('GPSLatitudeRef')
                    lon_dms = metadata_result["gps_info"].get('GPSLongitude')
                    lon_ref = metadata_result["gps_info"].get('GPSLongitudeRef')

                    if lat_dms and lat_ref and lon_dms and lon_ref:
                        dec_lat = _convert_gps_to_decimal(lat_dms, lat_ref)
                        dec_lon = _convert_gps_to_decimal(lon_dms, lon_ref)
                        if dec_lat is not None and dec_lon is not None:
                            metadata_result["gps_info"]["decimal_latitude"] = dec_lat
                            metadata_result["gps_info"]["decimal_longitude"] = dec_lon
                            metadata_result["gps_info"]["google_maps_link"] = f"https://www.google.com/maps?q={dec_lat},{dec_lon}"
                else:
                    # Process other EXIF tags
                    if isinstance(value, bytes):
                        # Attempt to decode bytes, replace errors if not valid UTF-8
                        try:
                            processed_value = value.decode('utf-8', errors='replace').strip()
                        except UnicodeDecodeError:
                            processed_value = f"[Binary data, {len(value)} bytes]"
                    elif isinstance(value, datetime): # Check for datetime objects specifically
                        processed_value = value.isoformat()
                    else:
                        processed_value = value # Keep as is (int, float, Rational, string, etc.)
                    
                    metadata_result["exif_data"][str(tag_name)] = processed_value # Ensure tag_name is string
        else:
            logger.debug("No EXIF data found in image.")

    except AttributeError: # If _getexif is not available (e.g. for PNGs sometimes)
        logger.debug("Image format does not support EXIF data (_getexif attribute missing).")
    except Exception as e:
        logger.error(f"Error during EXIF processing: {str(e)}")
        metadata_result["exif_processing_error"] = str(e)
        
    return metadata_result


def extract_from_url(image_url: str) -> Dict[str, Any]:
    """
    Extract EXIF metadata from an image at a URL.
    
    Args:
        image_url: URL of the image.
        
    Returns:
        Dictionary containing extracted metadata or an error.
    """
    logger.info(f"Attempting to extract EXIF metadata from URL: {image_url}")
    
    if not PIL_AVAILABLE:
        return {"url_input": image_url, "error": "Pillow (PIL) library not installed. Cannot process images."}
    
    if not is_valid_url(image_url):
        return {"url_input": image_url, "error": "Invalid URL format."}
    
    http_headers = {"User-Agent": DEFAULT_USER_AGENT}
    
    try:
        response = requests.get(image_url, headers=http_headers, timeout=DEFAULT_TIMEOUT, stream=True)
        response.raise_for_status()
        
        content_type = response.headers.get('Content-Type', '').lower()
        if not content_type.startswith('image/'):
            return {"url_input": image_url, "error": f"URL content-type is not an image: {content_type}"}
        
        image_filename = os.path.basename(urlparse(image_url).path) or "image_from_url"
        image_data_stream = io.BytesIO(response.content) # Read content into memory stream
        
        with Image.open(image_data_stream) as img:
            extracted_meta = _extract_metadata_from_image_obj(img)

        result = {
            "source_type": "url",
            "source_input": image_url,
            "image_filename_from_url": image_filename,
            "content_type_header": content_type,
            "image_size_bytes": len(response.content),
            "metadata": extracted_meta
        }
        logger.info(f"Successfully extracted metadata from URL: {image_url}")
        return result
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading image from {image_url}: {str(e)}")
        return {"url_input": image_url, "error": f"Image download error: {str(e)}"}
    except IOError as e: # Pillow can raise IOError for corrupt/unsupported images
        logger.error(f"Pillow (PIL) could not open or read image from {image_url}: {str(e)}")
        return {"url_input": image_url, "error": f"Image processing error (Pillow): {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error extracting metadata from URL {image_url}: {str(e)}")
        return {"url_input": image_url, "error": f"Unexpected error: {str(e)}"}


def extract_from_file(image_path: str) -> Dict[str, Any]:
    """
    Extract EXIF metadata from a local image file.
    
    Args:
        image_path: Path to the local image file.
        
    Returns:
        Dictionary containing extracted metadata or an error.
    """
    logger.info(f"Attempting to extract EXIF metadata from file: {image_path}")

    if not PIL_AVAILABLE:
        return {"file_input": image_path, "error": "Pillow (PIL) library not installed. Cannot process images."}
    
    if not os.path.isfile(image_path):
        return {"file_input": image_path, "error": "Image file not found at specified path."}
    
    try:
        with Image.open(image_path) as img:
            extracted_meta = _extract_metadata_from_image_obj(img)
            
        result = {
            "source_type": "file",
            "source_input": image_path,
            "image_filename": os.path.basename(image_path),
            "image_size_bytes": os.path.getsize(image_path),
            "metadata": extracted_meta
        }
        logger.info(f"Successfully extracted metadata from file: {image_path}")
        return result

    except IOError as e: # Pillow can raise IOError for corrupt/unsupported images
        logger.error(f"Pillow (PIL) could not open or read image file {image_path}: {str(e)}")
        return {"file_input": image_path, "error": f"Image processing error (Pillow): {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error extracting metadata from file {image_path}: {str(e)}")
        return {"file_input": image_path, "error": f"Unexpected error: {str(e)}"}


def analyze_image_security(image_path_or_url: str) -> Dict[str, Any]:
    """
    Analyze an image's metadata for potential security and privacy concerns.
    
    Args:
        image_path_or_url: Path to local image or URL of the image.
        
    Returns:
        Dictionary with security analysis results or an error.
    """
    logger.info(f"Analyzing image security for: {image_path_or_url}")

    # Determine if input is URL or file path and extract metadata
    if is_valid_url(image_path_or_url):
        metadata_extraction_result = extract_from_url(image_path_or_url)
    elif os.path.isfile(image_path_or_url):
        metadata_extraction_result = extract_from_file(image_path_or_url)
    else:
        return {"input_source": image_path_or_url, "error": "Invalid input. Provide a valid URL or file path."}
    
    if "error" in metadata_extraction_result:
        # Propagate the error from extraction
        return {"input_source": image_path_or_url, **metadata_extraction_result}

    analysis_report: Dict[str, Any] = { # Renamed and type hinted
        "source": image_path_or_url,
        "source_type": metadata_extraction_result.get("source_type"),
        "overall_privacy_risk": "Low", # Default risk
        "findings": [] # List of specific findings (type, details, severity)
    }
    
    metadata = metadata_extraction_result.get("metadata", {})
    exif_data = metadata.get("exif_data", {})
    gps_info = metadata.get("gps_info", {})

    # Check for GPS data (High Risk)
    if metadata.get("has_gps") and gps_info.get("decimal_latitude") is not None:
        analysis_report["overall_privacy_risk"] = "High"
        analysis_report["findings"].append({
            "type": "Geolocation Data",
            "details": f"Precise GPS coordinates found: Lat {gps_info['decimal_latitude']:.6f}, Lon {gps_info['decimal_longitude']:.6f}",
            "link": gps_info.get("google_maps_link", "N/A"),
            "severity": "High",
            "recommendation": "Remove GPS metadata before sharing to protect location privacy."
        })

    # Check for Device Information (Medium Risk if detailed)
    camera_make = exif_data.get("Make")
    camera_model = exif_data.get("Model")
    # Some cameras store unique serial numbers.
    # Common tags for serial numbers (vary by manufacturer):
    serial_tags = ["BodySerialNumber", "SerialNumber", "InternalSerialNumber", "CameraSerialNumber"]
    device_serial = next((exif_data[tag] for tag in serial_tags if tag in exif_data), None)

    if device_serial:
        analysis_report["overall_privacy_risk"] = max(analysis_report["overall_privacy_risk"], "Medium", key={"Low":0, "Medium":1, "High":2}.get) # type: ignore
        analysis_report["findings"].append({
            "type": "Device Serial Number",
            "details": f"Device serial number embedded: {device_serial}",
            "severity": "Medium",
            "recommendation": "Remove device serial number from metadata to prevent device tracking/identification."
        })
    elif camera_make or camera_model:
        details_str = f"Make: {camera_make or 'N/A'}, Model: {camera_model or 'N/A'}"
        analysis_report["findings"].append({
            "type": "Device Information",
            "details": f"Camera/device information: {details_str.strip()}",
            "severity": "Low",
            "recommendation": "Be aware that device make/model can be identified."
        })
        
    # Check for Software Information (Low to Medium Risk)
    software = exif_data.get("Software")
    if software:
        analysis_report["findings"].append({
            "type": "Software Information",
            "details": f"Software used for processing/capture: {software}",
            "severity": "Low",
            "recommendation": "Software information can sometimes hint at editing or specific device OS."
        })

    # Check for Timestamps (Low Risk, but can be sensitive)
    datetime_original = exif_data.get("DateTimeOriginal")
    if datetime_original:
        analysis_report["findings"].append({
            "type": "Creation Timestamp",
            "details": f"Image captured/created at: {datetime_original}",
            "severity": "Low",
            "recommendation": "Timestamps can reveal when and where (if combined with GPS) an image was taken."
        })

    # Check for Copyright/Author (Low to Medium, depends on intent)
    copyright_info = exif_data.get("Copyright")
    artist_info = exif_data.get("Artist")
    creator_info = None
    if copyright_info or artist_info:
        creator_info = f"Copyright: {copyright_info or 'N/A'}, Artist: {artist_info or 'N/A'}"
        analysis_report["findings"].append({
            "type": "Attribution Information",
            "details": creator_info.strip(),
            "severity": "Low", # Could be Medium if anonymity is desired
            "recommendation": "Ensure this information is intended to be public."
        })

    if not analysis_report["findings"]:
        analysis_report["findings"].append({
            "type": "No Major Privacy Risks Detected",
            "details": "Basic metadata analysis did not reveal common high-impact privacy risks (like GPS or serial numbers).",
            "severity": "Informational",
            "recommendation": "Always review metadata manually if images are highly sensitive."
        })
    
    return analysis_report

# Placeholder for future social media specific EXIF extraction - most platforms strip EXIF.
# def extract_from_social_media_url(url: str) -> Dict[str, Any]:
# This would require more complex scraping and is often fruitless for EXIF.

