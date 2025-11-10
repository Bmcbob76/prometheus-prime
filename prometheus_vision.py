"""
Prometheus Vision Module
Real computer vision capabilities using OpenCV, face_recognition, OCR, and more.
"""

import os
import sys
import cv2
import numpy as np
from typing import Dict, Any, List, Optional, Tuple
import json
from pathlib import Path
from datetime import datetime
import base64

# Multi-monitor screenshots
try:
    import mss
    MSS_AVAILABLE = True
except ImportError:
    MSS_AVAILABLE = False

# Face recognition
try:
    import face_recognition
    FACE_RECOGNITION_AVAILABLE = True
except ImportError:
    FACE_RECOGNITION_AVAILABLE = False

# OCR libraries
try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    import easyocr
    EASYOCR_AVAILABLE = True
except ImportError:
    EASYOCR_AVAILABLE = False

# QR/Barcode scanning
try:
    from pyzbar import pyzbar
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

# PIL for image processing
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class PrometheusVision:
    """Advanced computer vision capabilities for Prometheus."""

    def __init__(self, config_dir: str = None):
        """
        Initialize Prometheus Vision module.

        Args:
            config_dir: Directory for storing vision data (known faces, etc.)
        """
        self.config_dir = config_dir or os.path.join(
            os.path.expanduser("~"), ".prometheus", "vision"
        )
        os.makedirs(self.config_dir, exist_ok=True)

        # Known faces database
        self.faces_dir = os.path.join(self.config_dir, "known_faces")
        os.makedirs(self.faces_dir, exist_ok=True)

        # Initialize face recognition
        self.known_face_encodings = []
        self.known_face_names = []
        self._load_known_faces()

        # Initialize EasyOCR reader (lazy loading)
        self.easyocr_reader = None

        # YOLO model path
        self.yolo_dir = os.path.join(self.config_dir, "yolo")
        os.makedirs(self.yolo_dir, exist_ok=True)
        self.yolo_net = None
        self.yolo_classes = None

        # Haar cascade for face detection
        self.face_cascade = None
        self.eye_cascade = None
        self._init_haar_cascades()

        # Screenshots directory
        self.screenshots_dir = os.path.join(self.config_dir, "screenshots")
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def _init_haar_cascades(self):
        """Initialize Haar cascade classifiers for face/eye detection."""
        try:
            # Try to load from OpenCV data directory
            cascade_path = cv2.data.haarcascades
            self.face_cascade = cv2.CascadeClassifier(
                os.path.join(cascade_path, 'haarcascade_frontalface_default.xml')
            )
            self.eye_cascade = cv2.CascadeClassifier(
                os.path.join(cascade_path, 'haarcascade_eye.xml')
            )
        except Exception as e:
            print(f"Warning: Could not load Haar cascades: {e}")

    def _load_known_faces(self):
        """Load known faces from the database."""
        if not FACE_RECOGNITION_AVAILABLE:
            return

        self.known_face_encodings = []
        self.known_face_names = []

        # Load face encodings from saved files
        encodings_file = os.path.join(self.faces_dir, "encodings.json")
        if os.path.exists(encodings_file):
            try:
                with open(encodings_file, 'r') as f:
                    data = json.load(f)
                    for person in data:
                        name = person['name']
                        encoding = np.array(person['encoding'])
                        self.known_face_encodings.append(encoding)
                        self.known_face_names.append(name)
            except Exception as e:
                print(f"Error loading face encodings: {e}")

    def add_known_face(self, image_path: str, name: str) -> Dict[str, Any]:
        """
        Add a new face to the known faces database.

        Args:
            image_path: Path to image containing the face
            name: Name of the person

        Returns:
            Result dictionary with success status
        """
        if not FACE_RECOGNITION_AVAILABLE:
            return {
                "success": False,
                "error": "face_recognition library not available"
            }

        try:
            # Load image
            image = face_recognition.load_image_file(image_path)

            # Get face encodings
            face_encodings = face_recognition.face_encodings(image)

            if len(face_encodings) == 0:
                return {
                    "success": False,
                    "error": "No face detected in image"
                }

            # Use the first face found
            encoding = face_encodings[0]

            # Add to known faces
            self.known_face_encodings.append(encoding)
            self.known_face_names.append(name)

            # Save to database
            self._save_known_faces()

            return {
                "success": True,
                "name": name,
                "message": f"Successfully added {name} to known faces database"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _save_known_faces(self):
        """Save known faces database to disk."""
        encodings_file = os.path.join(self.faces_dir, "encodings.json")

        data = []
        for name, encoding in zip(self.known_face_names, self.known_face_encodings):
            data.append({
                "name": name,
                "encoding": encoding.tolist()
            })

        with open(encodings_file, 'w') as f:
            json.dump(data, f, indent=2)

    def detect_faces(self, image_path: str, method: str = "dnn") -> Dict[str, Any]:
        """
        Detect faces in an image using various methods.

        Args:
            image_path: Path to image file
            method: Detection method - 'dnn', 'haar', or 'hog'

        Returns:
            Dictionary with detected faces and their locations
        """
        try:
            if method == "haar":
                return self._detect_faces_haar(image_path)
            elif method == "hog":
                return self._detect_faces_hog(image_path)
            else:  # DNN
                return self._detect_faces_dnn(image_path)

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _detect_faces_haar(self, image_path: str) -> Dict[str, Any]:
        """Detect faces using Haar Cascade classifier."""
        if self.face_cascade is None:
            return {
                "success": False,
                "error": "Haar cascade not initialized"
            }

        # Load image
        img = cv2.imread(image_path)
        if img is None:
            return {
                "success": False,
                "error": "Could not load image"
            }

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # Detect faces
        faces = self.face_cascade.detectMultiScale(
            gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30)
        )

        face_locations = []
        for (x, y, w, h) in faces:
            face_locations.append({
                "x": int(x),
                "y": int(y),
                "width": int(w),
                "height": int(h)
            })

        return {
            "success": True,
            "method": "haar_cascade",
            "faces_detected": len(face_locations),
            "faces": face_locations
        }

    def _detect_faces_hog(self, image_path: str) -> Dict[str, Any]:
        """Detect faces using HOG (Histogram of Oriented Gradients)."""
        if not FACE_RECOGNITION_AVAILABLE:
            return {
                "success": False,
                "error": "face_recognition library not available"
            }

        # Load image
        image = face_recognition.load_image_file(image_path)

        # Detect faces
        face_locations = face_recognition.face_locations(image, model="hog")

        faces = []
        for (top, right, bottom, left) in face_locations:
            faces.append({
                "x": int(left),
                "y": int(top),
                "width": int(right - left),
                "height": int(bottom - top)
            })

        return {
            "success": True,
            "method": "hog",
            "faces_detected": len(faces),
            "faces": faces
        }

    def _detect_faces_dnn(self, image_path: str) -> Dict[str, Any]:
        """Detect faces using OpenCV DNN module."""
        try:
            # Load DNN model (using OpenCV's pre-trained model)
            model_file = "res10_300x300_ssd_iter_140000.caffemodel"
            config_file = "deploy.prototxt"

            # Note: These files would need to be downloaded separately
            # For now, fall back to Haar cascade
            return self._detect_faces_haar(image_path)

        except Exception as e:
            # Fallback to Haar cascade
            return self._detect_faces_haar(image_path)

    def recognize_faces(self, image_path: str, tolerance: float = 0.6) -> Dict[str, Any]:
        """
        Recognize faces in an image against the known faces database.

        Args:
            image_path: Path to image file
            tolerance: Face matching tolerance (lower = more strict)

        Returns:
            Dictionary with recognized faces and their names
        """
        if not FACE_RECOGNITION_AVAILABLE:
            return {
                "success": False,
                "error": "face_recognition library not available"
            }

        if len(self.known_face_encodings) == 0:
            return {
                "success": False,
                "error": "No known faces in database. Add faces first."
            }

        try:
            # Load image
            image = face_recognition.load_image_file(image_path)

            # Find faces
            face_locations = face_recognition.face_locations(image)
            face_encodings = face_recognition.face_encodings(image, face_locations)

            recognized_faces = []

            for face_encoding, face_location in zip(face_encodings, face_locations):
                # Compare with known faces
                matches = face_recognition.compare_faces(
                    self.known_face_encodings, face_encoding, tolerance=tolerance
                )
                name = "Unknown"
                confidence = 0.0

                # Find the best match
                face_distances = face_recognition.face_distance(
                    self.known_face_encodings, face_encoding
                )

                if len(face_distances) > 0:
                    best_match_index = np.argmin(face_distances)
                    if matches[best_match_index]:
                        name = self.known_face_names[best_match_index]
                        confidence = 1.0 - face_distances[best_match_index]

                top, right, bottom, left = face_location
                recognized_faces.append({
                    "name": name,
                    "confidence": float(confidence),
                    "location": {
                        "x": int(left),
                        "y": int(top),
                        "width": int(right - left),
                        "height": int(bottom - top)
                    }
                })

            return {
                "success": True,
                "faces_found": len(recognized_faces),
                "faces": recognized_faces
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def extract_text_ocr(
        self,
        image_path: str,
        engine: str = "tesseract",
        lang: str = "en"
    ) -> Dict[str, Any]:
        """
        Extract text from an image using OCR.

        Args:
            image_path: Path to image file
            engine: OCR engine - 'tesseract' or 'easyocr'
            lang: Language code (e.g., 'en', 'es', 'fr')

        Returns:
            Dictionary with extracted text and metadata
        """
        if engine == "tesseract":
            return self._extract_text_tesseract(image_path, lang)
        elif engine == "easyocr":
            return self._extract_text_easyocr(image_path, lang)
        else:
            return {
                "success": False,
                "error": f"Unknown OCR engine: {engine}"
            }

    def _extract_text_tesseract(self, image_path: str, lang: str) -> Dict[str, Any]:
        """Extract text using Tesseract OCR."""
        if not TESSERACT_AVAILABLE:
            return {
                "success": False,
                "error": "pytesseract not available"
            }

        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {
                    "success": False,
                    "error": "Could not load image"
                }

            # Convert to RGB (Tesseract expects RGB)
            rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

            # Extract text
            text = pytesseract.image_to_string(rgb, lang=lang)

            # Get detailed data
            data = pytesseract.image_to_data(rgb, lang=lang, output_type=pytesseract.Output.DICT)

            # Extract word-level information
            words = []
            n_boxes = len(data['text'])
            for i in range(n_boxes):
                if int(data['conf'][i]) > 0:  # Confidence > 0
                    words.append({
                        "text": data['text'][i],
                        "confidence": float(data['conf'][i]),
                        "x": int(data['left'][i]),
                        "y": int(data['top'][i]),
                        "width": int(data['width'][i]),
                        "height": int(data['height'][i])
                    })

            return {
                "success": True,
                "engine": "tesseract",
                "text": text.strip(),
                "words": words,
                "word_count": len([w for w in words if w['text'].strip()])
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _extract_text_easyocr(self, image_path: str, lang: str) -> Dict[str, Any]:
        """Extract text using EasyOCR."""
        if not EASYOCR_AVAILABLE:
            return {
                "success": False,
                "error": "easyocr not available"
            }

        try:
            # Initialize reader (lazy loading)
            if self.easyocr_reader is None:
                self.easyocr_reader = easyocr.Reader([lang])

            # Read text
            results = self.easyocr_reader.readtext(image_path)

            # Parse results
            words = []
            full_text = []

            for (bbox, text, confidence) in results:
                # bbox is [[x1,y1],[x2,y2],[x3,y3],[x4,y4]]
                x_coords = [point[0] for point in bbox]
                y_coords = [point[1] for point in bbox]

                x = int(min(x_coords))
                y = int(min(y_coords))
                width = int(max(x_coords) - x)
                height = int(max(y_coords) - y)

                words.append({
                    "text": text,
                    "confidence": float(confidence),
                    "x": x,
                    "y": y,
                    "width": width,
                    "height": height
                })
                full_text.append(text)

            return {
                "success": True,
                "engine": "easyocr",
                "text": " ".join(full_text),
                "words": words,
                "word_count": len(words)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def capture_screen(
        self,
        monitor_id: Optional[int] = None,
        region: Optional[Tuple[int, int, int, int]] = None
    ) -> Dict[str, Any]:
        """
        Capture screenshot from monitor(s).

        Args:
            monitor_id: Monitor number (None = all monitors, 0 = primary, 1+ = specific)
            region: Optional region (x, y, width, height) to capture

        Returns:
            Dictionary with screenshot path and metadata
        """
        if not MSS_AVAILABLE:
            return {
                "success": False,
                "error": "mss library not available"
            }

        try:
            with mss.mss() as sct:
                # Get monitor info
                monitors = sct.monitors

                # Determine which monitor to capture
                if monitor_id is None:
                    # Capture all monitors
                    monitor = monitors[0]  # All in one
                elif monitor_id >= len(monitors):
                    return {
                        "success": False,
                        "error": f"Monitor {monitor_id} not found. Available: 0-{len(monitors)-1}"
                    }
                else:
                    monitor = monitors[monitor_id]

                # Apply region if specified
                if region:
                    x, y, w, h = region
                    monitor = {
                        "top": monitor["top"] + y,
                        "left": monitor["left"] + x,
                        "width": w,
                        "height": h
                    }

                # Capture screenshot
                screenshot = sct.grab(monitor)

                # Save to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"screenshot_{timestamp}.png"
                filepath = os.path.join(self.screenshots_dir, filename)

                # Convert to PIL Image and save
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                img.save(filepath)

                return {
                    "success": True,
                    "filepath": filepath,
                    "monitor_id": monitor_id,
                    "width": screenshot.width,
                    "height": screenshot.height,
                    "available_monitors": len(monitors) - 1
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def detect_objects(
        self,
        image_path: str,
        confidence_threshold: float = 0.5
    ) -> Dict[str, Any]:
        """
        Detect objects in an image using YOLO.

        Args:
            image_path: Path to image file
            confidence_threshold: Minimum confidence for detection

        Returns:
            Dictionary with detected objects
        """
        # Note: This requires YOLO model files to be downloaded
        # For a production implementation, you would:
        # 1. Download YOLOv4 or YOLOv8 weights and config
        # 2. Load the model
        # 3. Run inference

        # For now, we'll provide a basic implementation using OpenCV's DNN module
        try:
            # Check if image exists
            if not os.path.exists(image_path):
                return {
                    "success": False,
                    "error": "Image file not found"
                }

            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {
                    "success": False,
                    "error": "Could not load image"
                }

            # For a real implementation, you would load YOLO here
            # Example:
            # net = cv2.dnn.readNet("yolov4.weights", "yolov4.cfg")
            # blob = cv2.dnn.blobFromImage(img, 1/255.0, (416, 416), swapRB=True, crop=False)
            # net.setInput(blob)
            # outputs = net.forward(output_layers)

            return {
                "success": False,
                "error": "YOLO model not configured. Download YOLOv4 weights and config files.",
                "message": "To enable object detection, download YOLO model files and configure the model path."
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def scan_qr_code(self, image_path: str) -> Dict[str, Any]:
        """
        Scan QR codes and barcodes in an image.

        Args:
            image_path: Path to image file

        Returns:
            Dictionary with decoded QR/barcode data
        """
        if not PYZBAR_AVAILABLE:
            return {
                "success": False,
                "error": "pyzbar library not available"
            }

        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {
                    "success": False,
                    "error": "Could not load image"
                }

            # Decode QR codes and barcodes
            decoded_objects = pyzbar.decode(img)

            codes = []
            for obj in decoded_objects:
                codes.append({
                    "type": obj.type,
                    "data": obj.data.decode('utf-8'),
                    "quality": obj.quality,
                    "x": obj.rect.left,
                    "y": obj.rect.top,
                    "width": obj.rect.width,
                    "height": obj.rect.height
                })

            return {
                "success": True,
                "codes_found": len(codes),
                "codes": codes
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """
        Perform comprehensive image analysis.

        Args:
            image_path: Path to image file

        Returns:
            Dictionary with various image analysis results
        """
        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {
                    "success": False,
                    "error": "Could not load image"
                }

            # Get basic properties
            height, width, channels = img.shape

            # Color analysis
            avg_color_per_row = np.average(img, axis=0)
            avg_color = np.average(avg_color_per_row, axis=0)

            # Convert to HSV for better color analysis
            hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)

            # Dominant color analysis
            dominant_colors = self._get_dominant_colors(img, k=5)

            # Brightness analysis
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            brightness = np.mean(gray)

            # Edge detection for complexity analysis
            edges = cv2.Canny(gray, 100, 200)
            edge_density = np.sum(edges > 0) / (height * width)

            return {
                "success": True,
                "dimensions": {
                    "width": int(width),
                    "height": int(height),
                    "channels": int(channels)
                },
                "colors": {
                    "average_bgr": [float(c) for c in avg_color],
                    "dominant_colors": dominant_colors,
                    "brightness": float(brightness)
                },
                "complexity": {
                    "edge_density": float(edge_density)
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _get_dominant_colors(self, img: np.ndarray, k: int = 5) -> List[Dict[str, Any]]:
        """Extract dominant colors from an image using k-means clustering."""
        try:
            # Reshape image to be a list of pixels
            pixels = img.reshape((-1, 3))
            pixels = np.float32(pixels)

            # Define criteria and apply k-means
            criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 100, 0.2)
            _, labels, centers = cv2.kmeans(
                pixels, k, None, criteria, 10, cv2.KMEANS_RANDOM_CENTERS
            )

            # Count labels to find popularity
            unique, counts = np.unique(labels, return_counts=True)

            # Sort by popularity
            sorted_indices = np.argsort(-counts)

            colors = []
            total_pixels = len(labels)

            for idx in sorted_indices:
                color_bgr = centers[idx]
                percentage = (counts[idx] / total_pixels) * 100

                colors.append({
                    "bgr": [float(c) for c in color_bgr],
                    "rgb": [float(color_bgr[2]), float(color_bgr[1]), float(color_bgr[0])],
                    "percentage": float(percentage)
                })

            return colors

        except Exception as e:
            return []

    def compare_images(self, image1_path: str, image2_path: str) -> Dict[str, Any]:
        """
        Compare two images for similarity.

        Args:
            image1_path: Path to first image
            image2_path: Path to second image

        Returns:
            Dictionary with similarity metrics
        """
        try:
            # Load images
            img1 = cv2.imread(image1_path)
            img2 = cv2.imread(image2_path)

            if img1 is None or img2 is None:
                return {
                    "success": False,
                    "error": "Could not load one or both images"
                }

            # Resize images to same size for comparison
            height = min(img1.shape[0], img2.shape[0])
            width = min(img1.shape[1], img2.shape[1])

            img1_resized = cv2.resize(img1, (width, height))
            img2_resized = cv2.resize(img2, (width, height))

            # Calculate structural similarity
            gray1 = cv2.cvtColor(img1_resized, cv2.COLOR_BGR2GRAY)
            gray2 = cv2.cvtColor(img2_resized, cv2.COLOR_BGR2GRAY)

            # Simple MSE-based similarity
            mse = np.mean((gray1 - gray2) ** 2)
            similarity = 100 * (1 - min(mse / 10000, 1))  # Normalize to 0-100

            # Histogram comparison
            hist1 = cv2.calcHist([img1_resized], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])
            hist2 = cv2.calcHist([img2_resized], [0, 1, 2], None, [8, 8, 8], [0, 256, 0, 256, 0, 256])

            hist1 = cv2.normalize(hist1, hist1).flatten()
            hist2 = cv2.normalize(hist2, hist2).flatten()

            hist_similarity = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL) * 100

            return {
                "success": True,
                "similarity_mse": float(similarity),
                "similarity_histogram": float(hist_similarity),
                "overall_similarity": float((similarity + hist_similarity) / 2),
                "dimensions_match": img1.shape == img2.shape
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_available_features(self) -> Dict[str, bool]:
        """Get status of available vision features based on installed libraries."""
        return {
            "opencv": True,  # Always available (required)
            "face_recognition": FACE_RECOGNITION_AVAILABLE,
            "tesseract_ocr": TESSERACT_AVAILABLE,
            "easyocr": EASYOCR_AVAILABLE,
            "qr_barcode_scanning": PYZBAR_AVAILABLE,
            "multi_monitor_capture": MSS_AVAILABLE,
            "pil_image_processing": PIL_AVAILABLE
        }


def main():
    """Demo and testing function."""
    vision = PrometheusVision()

    print("=" * 60)
    print("PROMETHEUS VISION MODULE - INITIALIZATION")
    print("=" * 60)

    # Show available features
    features = vision.get_available_features()
    print("\nAvailable Features:")
    for feature, available in features.items():
        status = "✓ Available" if available else "✗ Not Available"
        print(f"  {feature}: {status}")

    print("\nVision module initialized successfully!")
    print(f"Config directory: {vision.config_dir}")
    print(f"Known faces: {len(vision.known_face_names)}")

    print("\n" + "=" * 60)
    print("USAGE EXAMPLES:")
    print("=" * 60)
    print("""
# Face Recognition
vision = PrometheusVision()

# Add a known face
vision.add_known_face("path/to/photo.jpg", "John Doe")

# Detect faces
result = vision.detect_faces("path/to/image.jpg", method="haar")

# Recognize faces
result = vision.recognize_faces("path/to/image.jpg")

# OCR Text Extraction
result = vision.extract_text_ocr("path/to/document.jpg", engine="tesseract")

# Screenshot Capture
result = vision.capture_screen(monitor_id=0)  # Primary monitor
result = vision.capture_screen()  # All monitors

# QR/Barcode Scanning
result = vision.scan_qr_code("path/to/qr_code.jpg")

# Image Analysis
result = vision.analyze_image("path/to/image.jpg")

# Compare Images
result = vision.compare_images("image1.jpg", "image2.jpg")
    """)


if __name__ == "__main__":
    main()
