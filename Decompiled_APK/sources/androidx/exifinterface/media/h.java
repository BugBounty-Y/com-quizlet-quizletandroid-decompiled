package androidx.exifinterface.media;

import android.content.res.AssetManager;
import android.media.MediaMetadataRetriever;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;
import android.util.Pair;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Pattern;
import java.util.zip.CRC32;

/* loaded from: classes.dex */
public final class h {
    public static final byte[] A;
    public static final byte[] B;
    public static final byte[] C;
    public static final byte[] D;
    public static final byte[] E;
    public static final byte[] F;
    public static final byte[] G;
    public static final byte[] H;
    public static final byte[] I;
    public static final byte[] J;
    public static final byte[] K;
    public static final byte[] L;
    public static final byte[] M;
    public static final byte[] N;
    public static final byte[] O;
    public static final byte[] P;
    public static final byte[] Q;
    public static final String[] R;
    public static final int[] S;
    public static final byte[] T;
    public static final e U;
    public static final e[][] V;
    public static final e[] W;
    public static final HashMap[] X;
    public static final HashMap[] Y;
    public static final Set Z;
    public static final HashMap a0;
    public static final Charset b0;
    public static final byte[] c0;
    public static final byte[] d0;
    public static final Pattern e0;
    public static final Pattern f0;
    public static final Pattern g0;
    public static final boolean v = Log.isLoggable("ExifInterface", 3);
    public static final int[] w;
    public static final int[] x;
    public static final byte[] y;
    public static final byte[] z;
    public final String a;
    public final FileDescriptor b;
    public final AssetManager.AssetInputStream c;
    public int d;
    public final boolean e;
    public final HashMap[] f;
    public final HashSet g;
    public ByteOrder h;
    public boolean i;
    public boolean j;
    public boolean k;
    public int l;
    public int m;
    public byte[] n;
    public int o;
    public int p;
    public int q;
    public int r;
    public int s;
    public d t;
    public boolean u;

    static {
        Arrays.asList(1, 6, 3, 8);
        Arrays.asList(2, 7, 4, 5);
        w = new int[]{8, 8, 8};
        x = new int[]{8};
        y = new byte[]{-1, -40, -1};
        z = new byte[]{102, 116, 121, 112};
        A = new byte[]{109, 105, 102, 49};
        B = new byte[]{104, 101, 105, 99};
        C = new byte[]{97, 118, 105, 102};
        D = new byte[]{97, 118, 105, 115};
        E = new byte[]{79, 76, 89, 77, 80, 0};
        F = new byte[]{79, 76, 89, 77, 80, 85, 83, 0, 73, 73};
        G = new byte[]{-119, 80, 78, 71, 13, 10, 26, 10};
        H = "XML:com.adobe.xmp\u0000\u0000\u0000\u0000\u0000".getBytes(StandardCharsets.UTF_8);
        I = new byte[]{82, 73, 70, 70};
        J = new byte[]{87, 69, 66, 80};
        K = new byte[]{69, 88, 73, 70};
        L = new byte[]{-99, 1, 42};
        M = "VP8X".getBytes(Charset.defaultCharset());
        N = "VP8L".getBytes(Charset.defaultCharset());
        O = "VP8 ".getBytes(Charset.defaultCharset());
        P = "ANIM".getBytes(Charset.defaultCharset());
        Q = "ANMF".getBytes(Charset.defaultCharset());
        R = new String[]{"", "BYTE", "STRING", "USHORT", "ULONG", "URATIONAL", "SBYTE", "UNDEFINED", "SSHORT", "SLONG", "SRATIONAL", "SINGLE", "DOUBLE", "IFD"};
        S = new int[]{0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 1};
        T = new byte[]{65, 83, 67, 73, 73, 0, 0, 0};
        e[] eVarArr = {new e("NewSubfileType", 254, 4), new e("SubfileType", 255, 4), new e("ImageWidth", 256, 3, 4), new e("ImageLength", 257, 3, 4), new e("BitsPerSample", 258, 3), new e("Compression", 259, 3), new e("PhotometricInterpretation", 262, 3), new e("ImageDescription", SubsamplingScaleImageView.ORIENTATION_270, 2), new e("Make", 271, 2), new e("Model", 272, 2), new e("StripOffsets", 273, 3, 4), new e("Orientation", 274, 3), new e("SamplesPerPixel", 277, 3), new e("RowsPerStrip", 278, 3, 4), new e("StripByteCounts", 279, 3, 4), new e("XResolution", 282, 5), new e("YResolution", 283, 5), new e("PlanarConfiguration", 284, 3), new e("ResolutionUnit", 296, 3), new e("TransferFunction", 301, 3), new e("Software", 305, 2), new e("DateTime", 306, 2), new e("Artist", 315, 2), new e("WhitePoint", 318, 5), new e("PrimaryChromaticities", 319, 5), new e("SubIFDPointer", 330, 4), new e("JPEGInterchangeFormat", 513, 4), new e("JPEGInterchangeFormatLength", 514, 4), new e("YCbCrCoefficients", 529, 5), new e("YCbCrSubSampling", 530, 3), new e("YCbCrPositioning", 531, 3), new e("ReferenceBlackWhite", 532, 5), new e("Copyright", 33432, 2), new e("ExifIFDPointer", 34665, 4), new e("GPSInfoIFDPointer", 34853, 4), new e("SensorTopBorder", 4, 4), new e("SensorLeftBorder", 5, 4), new e("SensorBottomBorder", 6, 4), new e("SensorRightBorder", 7, 4), new e("ISO", 23, 3), new e("JpgFromRaw", 46, 7), new e("Xmp", 700, 1)};
        e[] eVarArr2 = {new e("ExposureTime", 33434, 5), new e("FNumber", 33437, 5), new e("ExposureProgram", 34850, 3), new e("SpectralSensitivity", 34852, 2), new e("PhotographicSensitivity", 34855, 3), new e("OECF", 34856, 7), new e("SensitivityType", 34864, 3), new e("StandardOutputSensitivity", 34865, 4), new e("RecommendedExposureIndex", 34866, 4), new e("ISOSpeed", 34867, 4), new e("ISOSpeedLatitudeyyy", 34868, 4), new e("ISOSpeedLatitudezzz", 34869, 4), new e("ExifVersion", 36864, 2), new e("DateTimeOriginal", 36867, 2), new e("DateTimeDigitized", 36868, 2), new e("OffsetTime", 36880, 2), new e("OffsetTimeOriginal", 36881, 2), new e("OffsetTimeDigitized", 36882, 2), new e("ComponentsConfiguration", 37121, 7), new e("CompressedBitsPerPixel", 37122, 5), new e("ShutterSpeedValue", 37377, 10), new e("ApertureValue", 37378, 5), new e("BrightnessValue", 37379, 10), new e("ExposureBiasValue", 37380, 10), new e("MaxApertureValue", 37381, 5), new e("SubjectDistance", 37382, 5), new e("MeteringMode", 37383, 3), new e("LightSource", 37384, 3), new e("Flash", 37385, 3), new e("FocalLength", 37386, 5), new e("SubjectArea", 37396, 3), new e("MakerNote", 37500, 7), new e("UserComment", 37510, 7), new e("SubSecTime", 37520, 2), new e("SubSecTimeOriginal", 37521, 2), new e("SubSecTimeDigitized", 37522, 2), new e("FlashpixVersion", 40960, 7), new e("ColorSpace", 40961, 3), new e("PixelXDimension", 40962, 3, 4), new e("PixelYDimension", 40963, 3, 4), new e("RelatedSoundFile", 40964, 2), new e("InteroperabilityIFDPointer", 40965, 4), new e("FlashEnergy", 41483, 5), new e("SpatialFrequencyResponse", 41484, 7), new e("FocalPlaneXResolution", 41486, 5), new e("FocalPlaneYResolution", 41487, 5), new e("FocalPlaneResolutionUnit", 41488, 3), new e("SubjectLocation", 41492, 3), new e("ExposureIndex", 41493, 5), new e("SensingMethod", 41495, 3), new e("FileSource", 41728, 7), new e("SceneType", 41729, 7), new e("CFAPattern", 41730, 7), new e("CustomRendered", 41985, 3), new e("ExposureMode", 41986, 3), new e("WhiteBalance", 41987, 3), new e("DigitalZoomRatio", 41988, 5), new e("FocalLengthIn35mmFilm", 41989, 3), new e("SceneCaptureType", 41990, 3), new e("GainControl", 41991, 3), new e("Contrast", 41992, 3), new e("Saturation", 41993, 3), new e("Sharpness", 41994, 3), new e("DeviceSettingDescription", 41995, 7), new e("SubjectDistanceRange", 41996, 3), new e("ImageUniqueID", 42016, 2), new e("CameraOwnerName", 42032, 2), new e("BodySerialNumber", 42033, 2), new e("LensSpecification", 42034, 5), new e("LensMake", 42035, 2), new e("LensModel", 42036, 2), new e("Gamma", 42240, 5), new e("DNGVersion", 50706, 1), new e("DefaultCropSize", 50720, 3, 4)};
        e[] eVarArr3 = {new e("GPSVersionID", 0, 1), new e("GPSLatitudeRef", 1, 2), new e("GPSLatitude", 2, 5, 10), new e("GPSLongitudeRef", 3, 2), new e("GPSLongitude", 4, 5, 10), new e("GPSAltitudeRef", 5, 1), new e("GPSAltitude", 6, 5), new e("GPSTimeStamp", 7, 5), new e("GPSSatellites", 8, 2), new e("GPSStatus", 9, 2), new e("GPSMeasureMode", 10, 2), new e("GPSDOP", 11, 5), new e("GPSSpeedRef", 12, 2), new e("GPSSpeed", 13, 5), new e("GPSTrackRef", 14, 2), new e("GPSTrack", 15, 5), new e("GPSImgDirectionRef", 16, 2), new e("GPSImgDirection", 17, 5), new e("GPSMapDatum", 18, 2), new e("GPSDestLatitudeRef", 19, 2), new e("GPSDestLatitude", 20, 5), new e("GPSDestLongitudeRef", 21, 2), new e("GPSDestLongitude", 22, 5), new e("GPSDestBearingRef", 23, 2), new e("GPSDestBearing", 24, 5), new e("GPSDestDistanceRef", 25, 2), new e("GPSDestDistance", 26, 5), new e("GPSProcessingMethod", 27, 7), new e("GPSAreaInformation", 28, 7), new e("GPSDateStamp", 29, 2), new e("GPSDifferential", 30, 3), new e("GPSHPositioningError", 31, 5)};
        e[] eVarArr4 = {new e("InteroperabilityIndex", 1, 2)};
        e[] eVarArr5 = {new e("NewSubfileType", 254, 4), new e("SubfileType", 255, 4), new e("ThumbnailImageWidth", 256, 3, 4), new e("ThumbnailImageLength", 257, 3, 4), new e("BitsPerSample", 258, 3), new e("Compression", 259, 3), new e("PhotometricInterpretation", 262, 3), new e("ImageDescription", SubsamplingScaleImageView.ORIENTATION_270, 2), new e("Make", 271, 2), new e("Model", 272, 2), new e("StripOffsets", 273, 3, 4), new e("ThumbnailOrientation", 274, 3), new e("SamplesPerPixel", 277, 3), new e("RowsPerStrip", 278, 3, 4), new e("StripByteCounts", 279, 3, 4), new e("XResolution", 282, 5), new e("YResolution", 283, 5), new e("PlanarConfiguration", 284, 3), new e("ResolutionUnit", 296, 3), new e("TransferFunction", 301, 3), new e("Software", 305, 2), new e("DateTime", 306, 2), new e("Artist", 315, 2), new e("WhitePoint", 318, 5), new e("PrimaryChromaticities", 319, 5), new e("SubIFDPointer", 330, 4), new e("JPEGInterchangeFormat", 513, 4), new e("JPEGInterchangeFormatLength", 514, 4), new e("YCbCrCoefficients", 529, 5), new e("YCbCrSubSampling", 530, 3), new e("YCbCrPositioning", 531, 3), new e("ReferenceBlackWhite", 532, 5), new e("Copyright", 33432, 2), new e("ExifIFDPointer", 34665, 4), new e("GPSInfoIFDPointer", 34853, 4), new e("DNGVersion", 50706, 1), new e("DefaultCropSize", 50720, 3, 4)};
        U = new e("StripOffsets", 273, 3);
        V = new e[][]{eVarArr, eVarArr2, eVarArr3, eVarArr4, eVarArr5, eVarArr, new e[]{new e("ThumbnailImage", 256, 7), new e("CameraSettingsIFDPointer", 8224, 4), new e("ImageProcessingIFDPointer", 8256, 4)}, new e[]{new e("PreviewImageStart", 257, 4), new e("PreviewImageLength", 258, 4)}, new e[]{new e("AspectFrame", 4371, 3)}, new e[]{new e("ColorSpace", 55, 3)}};
        W = new e[]{new e("SubIFDPointer", 330, 4), new e("ExifIFDPointer", 34665, 4), new e("GPSInfoIFDPointer", 34853, 4), new e("InteroperabilityIFDPointer", 40965, 4), new e("CameraSettingsIFDPointer", 8224, 1), new e("ImageProcessingIFDPointer", 8256, 1)};
        X = new HashMap[10];
        Y = new HashMap[10];
        Z = Collections.unmodifiableSet(new HashSet(Arrays.asList("FNumber", "DigitalZoomRatio", "ExposureTime", "SubjectDistance")));
        a0 = new HashMap();
        Charset charsetForName = Charset.forName("US-ASCII");
        b0 = charsetForName;
        c0 = "Exif\u0000\u0000".getBytes(charsetForName);
        d0 = "http://ns.adobe.com/xap/1.0/\u0000".getBytes(charsetForName);
        Locale locale = Locale.US;
        new SimpleDateFormat("yyyy:MM:dd HH:mm:ss", locale).setTimeZone(TimeZone.getTimeZone("UTC"));
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", locale).setTimeZone(TimeZone.getTimeZone("UTC"));
        int i = 0;
        while (true) {
            e[][] eVarArr6 = V;
            if (i >= eVarArr6.length) {
                HashMap map = a0;
                e[] eVarArr7 = W;
                map.put(Integer.valueOf(eVarArr7[0].a), 5);
                map.put(Integer.valueOf(eVarArr7[1].a), 1);
                map.put(Integer.valueOf(eVarArr7[2].a), 2);
                map.put(Integer.valueOf(eVarArr7[3].a), 3);
                map.put(Integer.valueOf(eVarArr7[4].a), 7);
                map.put(Integer.valueOf(eVarArr7[5].a), 8);
                Pattern.compile(".*[1-9].*");
                e0 = Pattern.compile("^(\\d{2}):(\\d{2}):(\\d{2})$");
                f0 = Pattern.compile("^(\\d{4}):(\\d{2}):(\\d{2})\\s(\\d{2}):(\\d{2}):(\\d{2})$");
                g0 = Pattern.compile("^(\\d{4})-(\\d{2})-(\\d{2})\\s(\\d{2}):(\\d{2}):(\\d{2})$");
                return;
            }
            X[i] = new HashMap();
            Y[i] = new HashMap();
            for (e eVar : eVarArr6[i]) {
                X[i].put(Integer.valueOf(eVar.a), eVar);
                Y[i].put(eVar.b, eVar);
            }
            i++;
        }
    }

    public h(String str) throws Throwable {
        FileInputStream fileInputStream;
        boolean z2;
        e[][] eVarArr = V;
        this.f = new HashMap[eVarArr.length];
        this.g = new HashSet(eVarArr.length);
        this.h = ByteOrder.BIG_ENDIAN;
        if (str == null) {
            throw new NullPointerException("filename cannot be null");
        }
        FileInputStream fileInputStream2 = null;
        this.c = null;
        this.a = str;
        try {
            fileInputStream = new FileInputStream(str);
        } catch (Throwable th) {
            th = th;
        }
        try {
            try {
                Os.lseek(fileInputStream.getFD(), 0L, OsConstants.SEEK_CUR);
                z2 = true;
            } catch (Exception unused) {
                z2 = false;
            }
            if (z2) {
                this.b = fileInputStream.getFD();
            } else {
                this.b = null;
            }
            s(fileInputStream);
            AbstractC3108b7.c(fileInputStream);
        } catch (Throwable th2) {
            th = th2;
            fileInputStream2 = fileInputStream;
            AbstractC3108b7.c(fileInputStream2);
            throw th;
        }
    }

    public static Pair p(String str) throws NumberFormatException {
        if (str.contains(",")) {
            String[] strArrSplit = str.split(",", -1);
            Pair pairP = p(strArrSplit[0]);
            if (((Integer) pairP.first).intValue() == 2) {
                return pairP;
            }
            for (int i = 1; i < strArrSplit.length; i++) {
                Pair pairP2 = p(strArrSplit[i]);
                int iIntValue = (((Integer) pairP2.first).equals(pairP.first) || ((Integer) pairP2.second).equals(pairP.first)) ? ((Integer) pairP.first).intValue() : -1;
                int iIntValue2 = (((Integer) pairP.second).intValue() == -1 || !(((Integer) pairP2.first).equals(pairP.second) || ((Integer) pairP2.second).equals(pairP.second))) ? -1 : ((Integer) pairP.second).intValue();
                if (iIntValue == -1 && iIntValue2 == -1) {
                    return new Pair(2, -1);
                }
                if (iIntValue == -1) {
                    pairP = new Pair(Integer.valueOf(iIntValue2), -1);
                } else if (iIntValue2 == -1) {
                    pairP = new Pair(Integer.valueOf(iIntValue), -1);
                }
            }
            return pairP;
        }
        if (!str.contains("/")) {
            try {
                try {
                    long j = Long.parseLong(str);
                    return (j < 0 || j > 65535) ? j < 0 ? new Pair(9, -1) : new Pair(4, -1) : new Pair(3, 4);
                } catch (NumberFormatException unused) {
                    return new Pair(2, -1);
                }
            } catch (NumberFormatException unused2) {
                Double.parseDouble(str);
                return new Pair(12, -1);
            }
        }
        String[] strArrSplit2 = str.split("/", -1);
        if (strArrSplit2.length == 2) {
            try {
                long j2 = (long) Double.parseDouble(strArrSplit2[0]);
                long j3 = (long) Double.parseDouble(strArrSplit2[1]);
                if (j2 >= 0 && j3 >= 0) {
                    if (j2 <= 2147483647L && j3 <= 2147483647L) {
                        return new Pair(10, 5);
                    }
                    return new Pair(5, -1);
                }
                return new Pair(10, -1);
            } catch (NumberFormatException unused3) {
            }
        }
        return new Pair(2, -1);
    }

    public static ByteOrder v(b bVar) throws IOException {
        short s = bVar.readShort();
        if (s == 18761) {
            return ByteOrder.LITTLE_ENDIAN;
        }
        if (s == 19789) {
            return ByteOrder.BIG_ENDIAN;
        }
        throw new IOException("Invalid byte order: " + Integer.toHexString(s));
    }

    /* JADX WARN: Removed duplicated region for block: B:102:0x0152  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00fa A[Catch: all -> 0x0103, Exception -> 0x0106, TryCatch #19 {Exception -> 0x0106, all -> 0x0103, blocks: (B:80:0x00f6, B:82:0x00fa, B:89:0x0118, B:88:0x0109), top: B:128:0x00f6 }] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0109 A[Catch: all -> 0x0103, Exception -> 0x0106, TryCatch #19 {Exception -> 0x0106, all -> 0x0103, blocks: (B:80:0x00f6, B:82:0x00fa, B:89:0x0118, B:88:0x0109), top: B:128:0x00f6 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void A() {
        /*
            Method dump skipped, instructions count: 370
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.A():void");
    }

    public final void B(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream) throws IOException {
        if (v) {
            Objects.toString(bufferedInputStream);
            Objects.toString(bufferedOutputStream);
        }
        b bVar = new b(bufferedInputStream);
        c cVar = new c(bufferedOutputStream, ByteOrder.BIG_ENDIAN);
        if (bVar.readByte() != -1) {
            throw new IOException("Invalid marker");
        }
        cVar.a(-1);
        if (bVar.readByte() != -40) {
            throw new IOException("Invalid marker");
        }
        cVar.a(-40);
        cVar.a(-1);
        cVar.a(-31);
        this.p = J(cVar);
        d dVar = this.t;
        byte[] bArr = d0;
        if (dVar != null) {
            cVar.write(-1);
            cVar.a(-31);
            cVar.j(bArr.length + 2 + this.t.d.length);
            cVar.write(bArr);
            cVar.write(this.t.d);
            this.u = true;
        }
        byte[] bArr2 = new byte[4096];
        while (bVar.readByte() == -1) {
            byte b = bVar.readByte();
            if (b == -39 || b == -38) {
                cVar.a(-1);
                cVar.a(b);
                AbstractC3108b7.f(bVar, cVar);
                return;
            }
            if (b != -31) {
                cVar.a(-1);
                cVar.a(b);
                int unsignedShort = bVar.readUnsignedShort();
                cVar.j(unsignedShort);
                int i = unsignedShort - 2;
                if (i < 0) {
                    throw new IOException("Invalid length");
                }
                while (i > 0) {
                    int i2 = bVar.read(bArr2, 0, Math.min(i, 4096));
                    if (i2 >= 0) {
                        cVar.write(bArr2, 0, i2);
                        i -= i2;
                    }
                }
            } else {
                int unsignedShort2 = bVar.readUnsignedShort();
                int length = unsignedShort2 - 2;
                if (length < 0) {
                    throw new IOException("Invalid length");
                }
                int length2 = bArr.length;
                byte[] bArr3 = c0;
                byte[] bArr4 = length >= length2 ? new byte[bArr.length] : length >= bArr3.length ? new byte[bArr3.length] : null;
                if (bArr4 != null) {
                    bVar.readFully(bArr4);
                    if (AbstractC3108b7.j(bArr4, bArr3) || AbstractC3108b7.j(bArr4, bArr)) {
                        bVar.a(length - bArr4.length);
                    }
                }
                cVar.a(-1);
                cVar.a(b);
                cVar.j(unsignedShort2);
                if (bArr4 != null) {
                    length -= bArr4.length;
                    cVar.write(bArr4);
                }
                while (length > 0) {
                    int i3 = bVar.read(bArr2, 0, Math.min(length, 4096));
                    if (i3 >= 0) {
                        cVar.write(bArr2, 0, i3);
                        length -= i3;
                    }
                }
            }
        }
        throw new IOException("Invalid marker");
    }

    /*  JADX ERROR: JadxOverflowException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxOverflowException: Regions count limit reached
        	at jadx.core.utils.ErrorsCounter.addError(ErrorsCounter.java:59)
        	at jadx.core.utils.ErrorsCounter.error(ErrorsCounter.java:31)
        	at jadx.core.dex.attributes.nodes.NotificationAttrNode.addError(NotificationAttrNode.java:19)
        */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0029 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x005d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x003d A[SYNTHETIC] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x005b -> B:10:0x0027). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void C(java.io.BufferedInputStream r9, java.io.BufferedOutputStream r10) {
        /*
            r8 = this;
            boolean r0 = androidx.exifinterface.media.h.v
            if (r0 == 0) goto La
            java.util.Objects.toString(r9)
            java.util.Objects.toString(r10)
        La:
            androidx.exifinterface.media.b r0 = new androidx.exifinterface.media.b
            r0.<init>(r9)
            androidx.exifinterface.media.c r9 = new androidx.exifinterface.media.c
            java.nio.ByteOrder r1 = java.nio.ByteOrder.BIG_ENDIAN
            r9.<init>(r10, r1)
            byte[] r10 = androidx.exifinterface.media.h.G
            int r10 = r10.length
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.e(r0, r9, r10)
            androidx.exifinterface.media.d r10 = r8.t
            r1 = 1
            r2 = 0
            if (r10 != 0) goto L26
            boolean r10 = r8.u
            if (r10 == 0) goto L5b
        L26:
            r10 = r1
        L27:
            if (r1 != 0) goto L30
            if (r10 == 0) goto L2c
            goto L30
        L2c:
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.f(r0, r9)
            return
        L30:
            int r3 = r0.readInt()
            int r4 = r0.readInt()
            r5 = 1229472850(0x49484452, float:820293.1)
            if (r4 != r5) goto L5d
            r9.d(r3)
            r9.d(r4)
            int r3 = r3 + 4
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.e(r0, r9, r3)
            int r3 = r8.p
            if (r3 != 0) goto L50
            r8.K(r9)
            r1 = r2
        L50:
            androidx.exifinterface.media.d r3 = r8.t
            if (r3 == 0) goto L27
            boolean r3 = r8.u
            if (r3 != 0) goto L27
            r8.L(r9)
        L5b:
            r10 = r2
            goto L27
        L5d:
            r5 = 1700284774(0x65584966, float:6.383657E22)
            if (r4 != r5) goto L6e
            if (r1 == 0) goto L6e
            r8.K(r9)
            int r3 = r3 + 4
            r0.a(r3)
            r1 = r2
            goto L27
        L6e:
            r5 = 1767135348(0x69545874, float:1.6044374E25)
            if (r4 != r5) goto La0
            byte[] r5 = androidx.exifinterface.media.h.H
            int r6 = r5.length
            if (r3 < r6) goto La0
            int r6 = r5.length
            byte[] r7 = new byte[r6]
            r0.readFully(r7)
            int r6 = r3 - r6
            int r6 = r6 + 4
            boolean r5 = java.util.Arrays.equals(r7, r5)
            if (r5 == 0) goto L93
            androidx.exifinterface.media.d r10 = r8.t
            if (r10 == 0) goto L8f
            r8.L(r9)
        L8f:
            r0.a(r6)
            goto L5b
        L93:
            r9.d(r3)
            r9.d(r4)
            r9.write(r7)
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.e(r0, r9, r6)
            goto L27
        La0:
            r9.d(r3)
            r9.d(r4)
            int r3 = r3 + 4
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.e(r0, r9, r3)
            goto L27
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.C(java.io.BufferedInputStream, java.io.BufferedOutputStream):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:115:0x0261 A[Catch: all -> 0x0229, Exception -> 0x022e, TRY_ENTER, TRY_LEAVE, TryCatch #13 {Exception -> 0x022e, all -> 0x0229, blocks: (B:115:0x0261, B:101:0x021f, B:110:0x023a), top: B:144:0x003c }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void D(java.io.BufferedInputStream r23, java.io.BufferedOutputStream r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 665
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.D(java.io.BufferedInputStream, java.io.BufferedOutputStream):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:140:0x027f  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x02c6  */
    /* JADX WARN: Removed duplicated region for block: B:156:0x0344  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x038e  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x03d0  */
    /* JADX WARN: Removed duplicated region for block: B:174:0x03fb  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0426  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x0437  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void E(java.lang.String r36, java.lang.String r37) {
        /*
            Method dump skipped, instructions count: 1136
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.E(java.lang.String, java.lang.String):void");
    }

    public final void F(b bVar) throws IOException {
        d dVar;
        HashMap map = this.f[4];
        d dVar2 = (d) map.get("Compression");
        if (dVar2 == null) {
            this.o = 6;
            q(bVar, map);
            return;
        }
        int i = dVar2.i(this.h);
        this.o = i;
        if (i != 1) {
            if (i == 6) {
                q(bVar, map);
                return;
            } else if (i != 7) {
                return;
            }
        }
        d dVar3 = (d) map.get("BitsPerSample");
        if (dVar3 != null) {
            int[] iArr = (int[]) dVar3.k(this.h);
            int[] iArr2 = w;
            if (!Arrays.equals(iArr2, iArr)) {
                if (this.d != 3 || (dVar = (d) map.get("PhotometricInterpretation")) == null) {
                    return;
                }
                int i2 = dVar.i(this.h);
                if ((i2 != 1 || !Arrays.equals(iArr, x)) && (i2 != 6 || !Arrays.equals(iArr, iArr2))) {
                    return;
                }
            }
            d dVar4 = (d) map.get("StripOffsets");
            d dVar5 = (d) map.get("StripByteCounts");
            if (dVar4 == null || dVar5 == null) {
                return;
            }
            long[] jArrD = AbstractC3108b7.d(dVar4.k(this.h));
            long[] jArrD2 = AbstractC3108b7.d(dVar5.k(this.h));
            if (jArrD == null || jArrD.length == 0) {
                Log.w("ExifInterface", "stripOffsets should not be null or have zero length.");
                return;
            }
            if (jArrD2 == null || jArrD2.length == 0) {
                Log.w("ExifInterface", "stripByteCounts should not be null or have zero length.");
                return;
            }
            if (jArrD.length != jArrD2.length) {
                Log.w("ExifInterface", "stripOffsets and stripByteCounts should have same length.");
                return;
            }
            long j = 0;
            for (long j2 : jArrD2) {
                j += j2;
            }
            int i3 = (int) j;
            byte[] bArr = new byte[i3];
            this.k = true;
            this.j = true;
            this.i = true;
            int i4 = 0;
            int i5 = 0;
            for (int i6 = 0; i6 < jArrD.length; i6++) {
                int i7 = (int) jArrD[i6];
                int i8 = (int) jArrD2[i6];
                if (i6 < jArrD.length - 1 && i7 + i8 != jArrD[i6 + 1]) {
                    this.k = false;
                }
                int i9 = i7 - i4;
                if (i9 < 0) {
                    return;
                }
                try {
                    bVar.a(i9);
                    int i10 = i4 + i9;
                    byte[] bArr2 = new byte[i8];
                    bVar.readFully(bArr2);
                    i4 = i10 + i8;
                    System.arraycopy(bArr2, 0, bArr, i5, i8);
                    i5 += i8;
                } catch (EOFException unused) {
                    return;
                }
            }
            this.n = bArr;
            if (this.k) {
                this.l = (int) jArrD[0];
                this.m = i3;
            }
        }
    }

    public final void G(int i, int i2) {
        HashMap[] mapArr = this.f;
        if (mapArr[i].isEmpty() || mapArr[i2].isEmpty()) {
            return;
        }
        d dVar = (d) mapArr[i].get("ImageLength");
        d dVar2 = (d) mapArr[i].get("ImageWidth");
        d dVar3 = (d) mapArr[i2].get("ImageLength");
        d dVar4 = (d) mapArr[i2].get("ImageWidth");
        if (dVar == null || dVar2 == null || dVar3 == null || dVar4 == null) {
            return;
        }
        int i3 = dVar.i(this.h);
        int i4 = dVar2.i(this.h);
        int i5 = dVar3.i(this.h);
        int i6 = dVar4.i(this.h);
        if (i3 >= i5 || i4 >= i6) {
            return;
        }
        HashMap map = mapArr[i];
        mapArr[i] = mapArr[i2];
        mapArr[i2] = map;
    }

    public final void H(g gVar, int i) throws IOException {
        d dVarF;
        d dVarF2;
        HashMap[] mapArr = this.f;
        d dVar = (d) mapArr[i].get("DefaultCropSize");
        d dVar2 = (d) mapArr[i].get("SensorTopBorder");
        d dVar3 = (d) mapArr[i].get("SensorLeftBorder");
        d dVar4 = (d) mapArr[i].get("SensorBottomBorder");
        d dVar5 = (d) mapArr[i].get("SensorRightBorder");
        if (dVar != null) {
            if (dVar.a == 5) {
                f[] fVarArr = (f[]) dVar.k(this.h);
                if (fVarArr == null || fVarArr.length != 2) {
                    Log.w("ExifInterface", "Invalid crop size values. cropSize=" + Arrays.toString(fVarArr));
                    return;
                } else {
                    dVarF = d.e(new f[]{fVarArr[0]}, this.h);
                    dVarF2 = d.e(new f[]{fVarArr[1]}, this.h);
                }
            } else {
                int[] iArr = (int[]) dVar.k(this.h);
                if (iArr == null || iArr.length != 2) {
                    Log.w("ExifInterface", "Invalid crop size values. cropSize=" + Arrays.toString(iArr));
                    return;
                }
                dVarF = d.f(iArr[0], this.h);
                dVarF2 = d.f(iArr[1], this.h);
            }
            mapArr[i].put("ImageWidth", dVarF);
            mapArr[i].put("ImageLength", dVarF2);
            return;
        }
        if (dVar2 != null && dVar3 != null && dVar4 != null && dVar5 != null) {
            int i2 = dVar2.i(this.h);
            int i3 = dVar4.i(this.h);
            int i4 = dVar5.i(this.h);
            int i5 = dVar3.i(this.h);
            if (i3 <= i2 || i4 <= i5) {
                return;
            }
            d dVarF3 = d.f(i3 - i2, this.h);
            d dVarF4 = d.f(i4 - i5, this.h);
            mapArr[i].put("ImageLength", dVarF3);
            mapArr[i].put("ImageWidth", dVarF4);
            return;
        }
        d dVar6 = (d) mapArr[i].get("ImageLength");
        d dVar7 = (d) mapArr[i].get("ImageWidth");
        if (dVar6 == null || dVar7 == null) {
            d dVar8 = (d) mapArr[i].get("JPEGInterchangeFormat");
            d dVar9 = (d) mapArr[i].get("JPEGInterchangeFormatLength");
            if (dVar8 == null || dVar9 == null) {
                return;
            }
            int i6 = dVar8.i(this.h);
            int i7 = dVar8.i(this.h);
            gVar.d(i6);
            byte[] bArr = new byte[i7];
            gVar.readFully(bArr);
            f(new b(bArr), i6, i);
        }
    }

    public final void I() {
        G(0, 5);
        G(0, 4);
        G(5, 4);
        HashMap[] mapArr = this.f;
        d dVar = (d) mapArr[1].get("PixelXDimension");
        d dVar2 = (d) mapArr[1].get("PixelYDimension");
        if (dVar != null && dVar2 != null) {
            mapArr[0].put("ImageWidth", dVar);
            mapArr[0].put("ImageLength", dVar2);
        }
        if (mapArr[4].isEmpty() && r(mapArr[5])) {
            mapArr[4] = mapArr[5];
            mapArr[5] = new HashMap();
        }
        r(mapArr[4]);
        z(0, "ThumbnailOrientation", "Orientation");
        z(0, "ThumbnailImageLength", "ImageLength");
        z(0, "ThumbnailImageWidth", "ImageWidth");
        z(5, "ThumbnailOrientation", "Orientation");
        z(5, "ThumbnailImageLength", "ImageLength");
        z(5, "ThumbnailImageWidth", "ImageWidth");
        z(4, "Orientation", "ThumbnailOrientation");
        z(4, "ImageLength", "ThumbnailImageLength");
        z(4, "ImageWidth", "ThumbnailImageWidth");
    }

    public final int J(c cVar) throws IOException {
        HashMap[] mapArr;
        int i;
        int i2;
        char c;
        char c2;
        int[] iArr;
        int i3;
        e[][] eVarArr = V;
        int[] iArr2 = new int[eVarArr.length];
        int[] iArr3 = new int[eVarArr.length];
        e[] eVarArr2 = W;
        for (e eVar : eVarArr2) {
            y(eVar.b);
        }
        if (this.i) {
            if (this.j) {
                y("StripOffsets");
                y("StripByteCounts");
            } else {
                y("JPEGInterchangeFormat");
                y("JPEGInterchangeFormatLength");
            }
        }
        int i4 = 0;
        while (true) {
            int length = eVarArr.length;
            mapArr = this.f;
            if (i4 >= length) {
                break;
            }
            Iterator it2 = mapArr[i4].entrySet().iterator();
            while (it2.hasNext()) {
                if (((Map.Entry) it2.next()).getValue() == null) {
                    it2.remove();
                }
            }
            i4++;
        }
        if (mapArr[1].isEmpty()) {
            i = 1;
            i2 = 0;
        } else {
            i = 1;
            i2 = 0;
            mapArr[0].put(eVarArr2[1].b, d.c(0L, this.h));
        }
        if (mapArr[2].isEmpty()) {
            c = 2;
        } else {
            c = 2;
            mapArr[i2].put(eVarArr2[2].b, d.c(0L, this.h));
        }
        if (mapArr[3].isEmpty()) {
            c2 = 3;
        } else {
            c2 = 3;
            mapArr[i].put(eVarArr2[3].b, d.c(0L, this.h));
        }
        int i5 = 4;
        if (this.i) {
            if (this.j) {
                mapArr[4].put("StripOffsets", d.f(i2, this.h));
                mapArr[4].put("StripByteCounts", d.f(this.m, this.h));
            } else {
                mapArr[4].put("JPEGInterchangeFormat", d.c(0L, this.h));
                mapArr[4].put("JPEGInterchangeFormatLength", d.c(this.m, this.h));
            }
        }
        int i6 = 0;
        while (true) {
            int length2 = eVarArr.length;
            iArr = S;
            if (i6 >= length2) {
                break;
            }
            Iterator it3 = mapArr[i6].entrySet().iterator();
            int i7 = 0;
            while (it3.hasNext()) {
                d dVar = (d) ((Map.Entry) it3.next()).getValue();
                dVar.getClass();
                int i8 = iArr[dVar.a] * dVar.b;
                if (i8 > 4) {
                    i7 += i8;
                }
            }
            iArr3[i6] = iArr3[i6] + i7;
            i6++;
        }
        int size = 8;
        for (int i9 = 0; i9 < eVarArr.length; i9++) {
            if (!mapArr[i9].isEmpty()) {
                iArr2[i9] = size;
                size = (mapArr[i9].size() * 12) + 6 + iArr3[i9] + size;
            }
        }
        if (this.i) {
            if (this.j) {
                mapArr[4].put("StripOffsets", d.f(size, this.h));
            } else {
                mapArr[4].put("JPEGInterchangeFormat", d.c(size, this.h));
            }
            this.l = size;
            size += this.m;
        }
        if (this.d == 4) {
            size += 8;
        }
        if (v) {
            for (int i10 = 0; i10 < eVarArr.length; i10++) {
                String.format("index: %d, offsets: %d, tag count: %d, data sizes: %d, total size: %d", Integer.valueOf(i10), Integer.valueOf(iArr2[i10]), Integer.valueOf(mapArr[i10].size()), Integer.valueOf(iArr3[i10]), Integer.valueOf(size));
            }
        }
        if (!mapArr[i].isEmpty()) {
            mapArr[0].put(eVarArr2[i].b, d.c(iArr2[i], this.h));
        }
        if (!mapArr[c].isEmpty()) {
            mapArr[0].put(eVarArr2[c].b, d.c(iArr2[c], this.h));
        }
        if (!mapArr[c2].isEmpty()) {
            mapArr[i].put(eVarArr2[c2].b, d.c(iArr2[c2], this.h));
        }
        int i11 = this.d;
        if (i11 == 4) {
            if (size > 65535) {
                throw new IllegalStateException(AbstractC0147y.c(size, "Size of exif data (", " bytes) exceeds the max size of a JPEG APP1 segment (65536 bytes)"));
            }
            cVar.j(size);
            cVar.write(c0);
        } else if (i11 == 13) {
            cVar.d(size);
            cVar.d(1700284774);
        } else if (i11 == 14) {
            cVar.write(K);
            cVar.d(size);
        }
        int size2 = cVar.a.size();
        cVar.f(this.h == ByteOrder.BIG_ENDIAN ? (short) 19789 : (short) 18761);
        cVar.b = this.h;
        cVar.j(42);
        cVar.i(8L);
        int i12 = 0;
        while (i12 < eVarArr.length) {
            if (mapArr[i12].isEmpty()) {
                i3 = i5;
            } else {
                cVar.j(mapArr[i12].size());
                int size3 = (mapArr[i12].size() * 12) + iArr2[i12] + 2 + i5;
                for (Map.Entry entry : mapArr[i12].entrySet()) {
                    int i13 = ((e) Y[i12].get(entry.getKey())).a;
                    d dVar2 = (d) entry.getValue();
                    dVar2.getClass();
                    int i14 = dVar2.a;
                    int i15 = iArr[i14];
                    int i16 = dVar2.b;
                    int i17 = i15 * i16;
                    cVar.j(i13);
                    cVar.j(i14);
                    cVar.d(i16);
                    if (i17 > 4) {
                        cVar.i(size3);
                        size3 += i17;
                    } else {
                        cVar.write(dVar2.d);
                        if (i17 < 4) {
                            while (i17 < 4) {
                                cVar.a(0);
                                i17++;
                            }
                        }
                    }
                    i5 = 4;
                }
                int i18 = i5;
                if (i12 != 0 || mapArr[i18].isEmpty()) {
                    cVar.i(0L);
                } else {
                    cVar.i(iArr2[i18]);
                }
                Iterator it4 = mapArr[i12].entrySet().iterator();
                while (it4.hasNext()) {
                    byte[] bArr = ((d) ((Map.Entry) it4.next()).getValue()).d;
                    if (bArr.length > 4) {
                        cVar.write(bArr, 0, bArr.length);
                    }
                }
                i3 = 4;
            }
            i12++;
            i5 = i3;
        }
        if (this.i) {
            cVar.write(n());
        }
        if (this.d == 14 && size % 2 == i) {
            cVar.a(0);
        }
        cVar.b = ByteOrder.BIG_ENDIAN;
        return size2;
    }

    public final void K(c cVar) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        this.p = cVar.a.size() + J(new c(byteArrayOutputStream, ByteOrder.BIG_ENDIAN));
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        cVar.write(byteArray);
        CRC32 crc32 = new CRC32();
        crc32.update(byteArray, 4, byteArray.length - 4);
        cVar.d((int) crc32.getValue());
    }

    public final void L(c cVar) throws IOException {
        cVar.d(this.t.d.length + 22);
        CRC32 crc32 = new CRC32();
        cVar.d(1767135348);
        crc32.update(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED);
        crc32.update(26964);
        crc32.update(6902872);
        crc32.update(1767135348);
        byte[] bArr = H;
        cVar.write(bArr);
        crc32.update(bArr);
        cVar.write(this.t.d);
        crc32.update(this.t.d);
        cVar.d((int) crc32.getValue());
        this.u = true;
    }

    public final void a() {
        String strB = b("DateTimeOriginal");
        HashMap[] mapArr = this.f;
        if (strB != null && b("DateTime") == null) {
            mapArr[0].put("DateTime", d.b(strB));
        }
        if (b("ImageWidth") == null) {
            mapArr[0].put("ImageWidth", d.c(0L, this.h));
        }
        if (b("ImageLength") == null) {
            mapArr[0].put("ImageLength", d.c(0L, this.h));
        }
        if (b("Orientation") == null) {
            mapArr[0].put("Orientation", d.c(0L, this.h));
        }
        if (b("LightSource") == null) {
            mapArr[1].put("LightSource", d.c(0L, this.h));
        }
    }

    public final String b(String str) {
        if (str == null) {
            throw new NullPointerException("tag shouldn't be null");
        }
        d dVarD = d(str);
        if (dVarD != null) {
            if (str.equals("GPSTimeStamp")) {
                int i = dVarD.a;
                if (i != 5 && i != 10) {
                    Log.w("ExifInterface", "GPS Timestamp format is not rational. format=" + i);
                    return null;
                }
                f[] fVarArr = (f[]) dVarD.k(this.h);
                if (fVarArr == null || fVarArr.length != 3) {
                    Log.w("ExifInterface", "Invalid GPS Timestamp array. array=" + Arrays.toString(fVarArr));
                    return null;
                }
                f fVar = fVarArr[0];
                Integer numValueOf = Integer.valueOf((int) (fVar.a / fVar.b));
                f fVar2 = fVarArr[1];
                Integer numValueOf2 = Integer.valueOf((int) (fVar2.a / fVar2.b));
                f fVar3 = fVarArr[2];
                return String.format("%02d:%02d:%02d", numValueOf, numValueOf2, Integer.valueOf((int) (fVar3.a / fVar3.b)));
            }
            if (!Z.contains(str)) {
                return dVarD.j(this.h);
            }
            try {
                return Double.toString(dVarD.h(this.h));
            } catch (NumberFormatException unused) {
            }
        }
        return null;
    }

    public final int c(int i, String str) {
        d dVarD = d(str);
        if (dVarD == null) {
            return i;
        }
        try {
            return dVarD.i(this.h);
        } catch (NumberFormatException unused) {
            return i;
        }
    }

    public final d d(String str) {
        d dVar;
        int i;
        d dVar2;
        if (str == null) {
            throw new NullPointerException("tag shouldn't be null");
        }
        if ("ISOSpeedRatings".equals(str)) {
            str = "PhotographicSensitivity";
        }
        if ("Xmp".equals(str) && (i = this.d) != 4 && ((i == 9 || i == 15 || i == 12 || i == 13) && (dVar2 = this.t) != null)) {
            return dVar2;
        }
        for (int i2 = 0; i2 < V.length; i2++) {
            d dVar3 = (d) this.f[i2].get(str);
            if (dVar3 != null) {
                return dVar3;
            }
        }
        if (!"Xmp".equals(str) || (dVar = this.t) == null) {
            return null;
        }
        return dVar;
    }

    public final void e(g gVar, int i) throws IOException {
        String strExtractMetadata;
        String strExtractMetadata2;
        String strExtractMetadata3;
        int i2 = Build.VERSION.SDK_INT;
        if (i2 < 28) {
            throw new UnsupportedOperationException("Reading EXIF from HEIC files is supported from SDK 28 and above");
        }
        if (i == 15 && i2 < 31) {
            throw new UnsupportedOperationException("Reading EXIF from AVIF files is supported from SDK 31 and above");
        }
        MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
        try {
            try {
                mediaMetadataRetriever.setDataSource(new a(gVar));
                String strExtractMetadata4 = mediaMetadataRetriever.extractMetadata(33);
                String strExtractMetadata5 = mediaMetadataRetriever.extractMetadata(34);
                String strExtractMetadata6 = mediaMetadataRetriever.extractMetadata(26);
                String strExtractMetadata7 = mediaMetadataRetriever.extractMetadata(17);
                if ("yes".equals(strExtractMetadata6)) {
                    strExtractMetadata = mediaMetadataRetriever.extractMetadata(29);
                    strExtractMetadata3 = mediaMetadataRetriever.extractMetadata(30);
                    strExtractMetadata2 = mediaMetadataRetriever.extractMetadata(31);
                } else if ("yes".equals(strExtractMetadata7)) {
                    strExtractMetadata = mediaMetadataRetriever.extractMetadata(18);
                    strExtractMetadata3 = mediaMetadataRetriever.extractMetadata(19);
                    strExtractMetadata2 = mediaMetadataRetriever.extractMetadata(24);
                } else {
                    strExtractMetadata = null;
                    strExtractMetadata2 = null;
                    strExtractMetadata3 = null;
                }
                HashMap[] mapArr = this.f;
                if (strExtractMetadata != null) {
                    mapArr[0].put("ImageWidth", d.f(Integer.parseInt(strExtractMetadata), this.h));
                }
                if (strExtractMetadata3 != null) {
                    mapArr[0].put("ImageLength", d.f(Integer.parseInt(strExtractMetadata3), this.h));
                }
                if (strExtractMetadata2 != null) {
                    int i3 = Integer.parseInt(strExtractMetadata2);
                    mapArr[0].put("Orientation", d.f(i3 != 90 ? i3 != 180 ? i3 != 270 ? 1 : 8 : 3 : 6, this.h));
                }
                if (strExtractMetadata4 != null && strExtractMetadata5 != null) {
                    int i4 = Integer.parseInt(strExtractMetadata4);
                    int i5 = Integer.parseInt(strExtractMetadata5);
                    if (i5 <= 6) {
                        throw new IOException("Invalid exif length");
                    }
                    gVar.d(i4);
                    byte[] bArr = new byte[6];
                    gVar.readFully(bArr);
                    int i6 = i4 + 6;
                    int i7 = i5 - 6;
                    if (!Arrays.equals(bArr, c0)) {
                        throw new IOException("Invalid identifier");
                    }
                    byte[] bArr2 = new byte[i7];
                    gVar.readFully(bArr2);
                    this.p = i6;
                    w(0, bArr2);
                }
                String strExtractMetadata8 = mediaMetadataRetriever.extractMetadata(41);
                String strExtractMetadata9 = mediaMetadataRetriever.extractMetadata(42);
                if (strExtractMetadata8 != null && strExtractMetadata9 != null) {
                    int i8 = Integer.parseInt(strExtractMetadata8);
                    int i9 = Integer.parseInt(strExtractMetadata9);
                    long j = i8;
                    gVar.d(j);
                    byte[] bArr3 = new byte[i9];
                    gVar.readFully(bArr3);
                    this.t = new d(j, bArr3, 1, i9);
                    this.u = true;
                }
                try {
                    mediaMetadataRetriever.release();
                } catch (IOException unused) {
                }
            } finally {
            }
        } catch (RuntimeException e) {
            throw new UnsupportedOperationException("Failed to read EXIF from HEIF file. Given stream is either malformed or unsupported.", e);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:61:0x011e, code lost:
    
        r21.c = r20.h;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x0122, code lost:
    
        return;
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:29:0x005c. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:30:0x005f. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:31:0x0062. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:34:0x006a A[FALL_THROUGH] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x010b A[LOOP:0: B:10:0x0023->B:56:0x010b, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0112 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(androidx.exifinterface.media.b r21, int r22, int r23) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 408
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.f(androidx.exifinterface.media.b, int, int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:115:0x015c A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:117:0x015f  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0126 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:166:0x00eb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00ea A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0124 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(java.io.BufferedInputStream r19) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 438
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.g(java.io.BufferedInputStream):int");
    }

    public final void h(g gVar) throws IOException {
        int i;
        int i2;
        k(gVar);
        HashMap[] mapArr = this.f;
        d dVar = (d) mapArr[1].get("MakerNote");
        if (dVar != null) {
            g gVar2 = new g(dVar.d);
            gVar2.c = this.h;
            byte[] bArr = E;
            byte[] bArr2 = new byte[bArr.length];
            gVar2.readFully(bArr2);
            gVar2.d(0L);
            byte[] bArr3 = F;
            byte[] bArr4 = new byte[bArr3.length];
            gVar2.readFully(bArr4);
            if (Arrays.equals(bArr2, bArr)) {
                gVar2.d(8L);
            } else if (Arrays.equals(bArr4, bArr3)) {
                gVar2.d(12L);
            }
            x(gVar2, 6);
            d dVar2 = (d) mapArr[7].get("PreviewImageStart");
            d dVar3 = (d) mapArr[7].get("PreviewImageLength");
            if (dVar2 != null && dVar3 != null) {
                mapArr[5].put("JPEGInterchangeFormat", dVar2);
                mapArr[5].put("JPEGInterchangeFormatLength", dVar3);
            }
            d dVar4 = (d) mapArr[8].get("AspectFrame");
            if (dVar4 != null) {
                int[] iArr = (int[]) dVar4.k(this.h);
                if (iArr == null || iArr.length != 4) {
                    Log.w("ExifInterface", "Invalid aspect frame values. frame=" + Arrays.toString(iArr));
                    return;
                }
                int i3 = iArr[2];
                int i4 = iArr[0];
                if (i3 <= i4 || (i = iArr[3]) <= (i2 = iArr[1])) {
                    return;
                }
                int i5 = (i3 - i4) + 1;
                int i6 = (i - i2) + 1;
                if (i5 < i6) {
                    int i7 = i5 + i6;
                    i6 = i7 - i6;
                    i5 = i7 - i6;
                }
                d dVarF = d.f(i5, this.h);
                d dVarF2 = d.f(i6, this.h);
                mapArr[0].put("ImageWidth", dVarF);
                mapArr[0].put("ImageLength", dVarF2);
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0047, code lost:
    
        r18.u = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x0049, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(androidx.exifinterface.media.b r19) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.i(androidx.exifinterface.media.b):void");
    }

    public final void j(b bVar) throws IOException {
        if (v) {
            Objects.toString(bVar);
        }
        bVar.a(84);
        byte[] bArr = new byte[4];
        byte[] bArr2 = new byte[4];
        byte[] bArr3 = new byte[4];
        bVar.readFully(bArr);
        bVar.readFully(bArr2);
        bVar.readFully(bArr3);
        int i = ByteBuffer.wrap(bArr).getInt();
        int i2 = ByteBuffer.wrap(bArr2).getInt();
        int i3 = ByteBuffer.wrap(bArr3).getInt();
        byte[] bArr4 = new byte[i2];
        bVar.a(i - bVar.b);
        bVar.readFully(bArr4);
        f(new b(bArr4), i, 5);
        bVar.a(i3 - bVar.b);
        bVar.c = ByteOrder.BIG_ENDIAN;
        int i4 = bVar.readInt();
        for (int i5 = 0; i5 < i4; i5++) {
            int unsignedShort = bVar.readUnsignedShort();
            int unsignedShort2 = bVar.readUnsignedShort();
            if (unsignedShort == U.a) {
                short s = bVar.readShort();
                short s2 = bVar.readShort();
                d dVarF = d.f(s, this.h);
                d dVarF2 = d.f(s2, this.h);
                HashMap[] mapArr = this.f;
                mapArr[0].put("ImageLength", dVarF);
                mapArr[0].put("ImageWidth", dVarF2);
                return;
            }
            bVar.a(unsignedShort2);
        }
    }

    public final void k(g gVar) throws IOException {
        t(gVar);
        x(gVar, 0);
        H(gVar, 0);
        H(gVar, 5);
        H(gVar, 4);
        I();
        if (this.d == 8) {
            HashMap[] mapArr = this.f;
            d dVar = (d) mapArr[1].get("MakerNote");
            if (dVar != null) {
                g gVar2 = new g(dVar.d);
                gVar2.c = this.h;
                gVar2.a(6);
                x(gVar2, 9);
                d dVar2 = (d) mapArr[9].get("ColorSpace");
                if (dVar2 != null) {
                    mapArr[1].put("ColorSpace", dVar2);
                }
            }
        }
    }

    public final void l(g gVar) throws IOException {
        if (v) {
            Objects.toString(gVar);
        }
        k(gVar);
        HashMap[] mapArr = this.f;
        d dVar = (d) mapArr[0].get("JpgFromRaw");
        if (dVar != null) {
            f(new b(dVar.d), (int) dVar.c, 5);
        }
        d dVar2 = (d) mapArr[0].get("ISO");
        d dVar3 = (d) mapArr[1].get("PhotographicSensitivity");
        if (dVar2 == null || dVar3 != null) {
            return;
        }
        mapArr[1].put("PhotographicSensitivity", dVar2);
    }

    public final boolean m(g gVar) throws IOException {
        byte[] bArr = c0;
        byte[] bArr2 = new byte[bArr.length];
        gVar.readFully(bArr2);
        if (!Arrays.equals(bArr2, bArr)) {
            Log.w("ExifInterface", "Given data is not EXIF-only.");
            return false;
        }
        byte[] bArrCopyOf = new byte[1024];
        int i = 0;
        while (true) {
            if (i == bArrCopyOf.length) {
                bArrCopyOf = Arrays.copyOf(bArrCopyOf, bArrCopyOf.length * 2);
            }
            int i2 = gVar.a.read(bArrCopyOf, i, bArrCopyOf.length - i);
            if (i2 == -1) {
                byte[] bArrCopyOf2 = Arrays.copyOf(bArrCopyOf, i);
                this.p = bArr.length;
                w(0, bArrCopyOf2);
                return true;
            }
            i += i2;
            gVar.b += i2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x0070 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:59:0x008a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0098 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:70:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final byte[] n() throws java.lang.Throwable {
        /*
            r9 = this;
            java.lang.String r0 = "Error closing fd."
            java.lang.String r1 = "ExifInterfaceUtils"
            boolean r2 = r9.i
            r3 = 0
            if (r2 != 0) goto Lb
            goto La0
        Lb:
            byte[] r2 = r9.n
            if (r2 == 0) goto L10
            return r2
        L10:
            android.content.res.AssetManager$AssetInputStream r2 = r9.c     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            if (r2 == 0) goto L2d
            boolean r4 = r2.markSupported()     // Catch: java.lang.Throwable -> L1f java.lang.Exception -> L26
            if (r4 == 0) goto L29
            r2.reset()     // Catch: java.lang.Throwable -> L1f java.lang.Exception -> L26
        L1d:
            r4 = r3
            goto L55
        L1f:
            r4 = move-exception
            r8 = r3
            r3 = r2
            r2 = r4
            r4 = r8
            goto L85
        L26:
            r4 = r3
            goto L93
        L29:
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.c(r2)
            return r3
        L2d:
            java.lang.String r2 = r9.a     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            if (r2 == 0) goto L40
            java.io.FileInputStream r2 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            java.lang.String r4 = r9.a     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            r2.<init>(r4)     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            goto L1d
        L39:
            r4 = move-exception
            r2 = r4
            r4 = r3
            goto L85
        L3d:
            r2 = r3
            r4 = r2
            goto L93
        L40:
            java.io.FileDescriptor r2 = r9.b     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            java.io.FileDescriptor r2 = android.system.Os.dup(r2)     // Catch: java.lang.Throwable -> L39 java.lang.Exception -> L3d
            int r4 = android.system.OsConstants.SEEK_SET     // Catch: java.lang.Throwable -> L7e java.lang.Exception -> L82
            r5 = 0
            android.system.Os.lseek(r2, r5, r4)     // Catch: java.lang.Throwable -> L7e java.lang.Exception -> L82
            java.io.FileInputStream r4 = new java.io.FileInputStream     // Catch: java.lang.Throwable -> L7e java.lang.Exception -> L82
            r4.<init>(r2)     // Catch: java.lang.Throwable -> L7e java.lang.Exception -> L82
            r8 = r4
            r4 = r2
            r2 = r8
        L55:
            androidx.exifinterface.media.b r5 = new androidx.exifinterface.media.b     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            r5.<init>(r2)     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            int r6 = r9.l     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            int r7 = r9.p     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            int r6 = r6 + r7
            r5.a(r6)     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            int r6 = r9.m     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            byte[] r6 = new byte[r6]     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            r5.readFully(r6)     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            r9.n = r6     // Catch: java.lang.Throwable -> L79 java.lang.Exception -> L93
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.c(r2)
            if (r4 == 0) goto L78
            android.system.Os.close(r4)     // Catch: android.system.ErrnoException -> L74
            return r6
        L74:
            r2 = move-exception
            android.util.Log.e(r1, r0, r2)
        L78:
            return r6
        L79:
            r3 = move-exception
            r8 = r3
            r3 = r2
        L7c:
            r2 = r8
            goto L85
        L7e:
            r4 = move-exception
            r8 = r4
            r4 = r2
            goto L7c
        L82:
            r4 = r2
            r2 = r3
            goto L93
        L85:
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.c(r3)
            if (r4 == 0) goto L92
            android.system.Os.close(r4)     // Catch: android.system.ErrnoException -> L8e
            goto L92
        L8e:
            r3 = move-exception
            android.util.Log.e(r1, r0, r3)
        L92:
            throw r2
        L93:
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3108b7.c(r2)
            if (r4 == 0) goto La0
            android.system.Os.close(r4)     // Catch: android.system.ErrnoException -> L9c
            goto La0
        L9c:
            r2 = move-exception
            android.util.Log.e(r1, r0, r2)
        La0:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.n():byte[]");
    }

    public final void o(b bVar) throws IOException {
        if (v) {
            Objects.toString(bVar);
        }
        bVar.c = ByteOrder.LITTLE_ENDIAN;
        bVar.a(I.length);
        int i = bVar.readInt() + 8;
        byte[] bArr = J;
        bVar.a(bArr.length);
        int length = bArr.length + 8;
        while (true) {
            try {
                byte[] bArr2 = new byte[4];
                bVar.readFully(bArr2);
                int i2 = bVar.readInt();
                int i3 = length + 8;
                if (Arrays.equals(K, bArr2)) {
                    byte[] bArrCopyOfRange = new byte[i2];
                    bVar.readFully(bArrCopyOfRange);
                    byte[] bArr3 = c0;
                    if (AbstractC3108b7.j(bArrCopyOfRange, bArr3)) {
                        bArrCopyOfRange = Arrays.copyOfRange(bArrCopyOfRange, bArr3.length, i2);
                    }
                    this.p = i3;
                    w(0, bArrCopyOfRange);
                    F(new b(bArrCopyOfRange));
                    return;
                }
                if (i2 % 2 == 1) {
                    i2++;
                }
                length = i3 + i2;
                if (length == i) {
                    return;
                }
                if (length > i) {
                    throw new IOException("Encountered WebP file with invalid chunk size");
                }
                bVar.a(i2);
            } catch (EOFException e) {
                throw new IOException("Encountered corrupt WebP file.", e);
            }
        }
    }

    public final void q(b bVar, HashMap map) throws IOException {
        d dVar = (d) map.get("JPEGInterchangeFormat");
        d dVar2 = (d) map.get("JPEGInterchangeFormatLength");
        if (dVar == null || dVar2 == null) {
            return;
        }
        int i = dVar.i(this.h);
        int i2 = dVar2.i(this.h);
        if (this.d == 7) {
            i += this.q;
        }
        if (i <= 0 || i2 <= 0) {
            return;
        }
        this.i = true;
        if (this.a == null && this.c == null && this.b == null) {
            byte[] bArr = new byte[i2];
            bVar.a(i);
            bVar.readFully(bArr);
            this.n = bArr;
        }
        this.l = i;
        this.m = i2;
    }

    public final boolean r(HashMap map) {
        d dVar = (d) map.get("ImageLength");
        d dVar2 = (d) map.get("ImageWidth");
        if (dVar == null || dVar2 == null) {
            return false;
        }
        return dVar.i(this.h) <= 512 && dVar2.i(this.h) <= 512;
    }

    public final void s(InputStream inputStream) {
        boolean z2 = v;
        for (int i = 0; i < V.length; i++) {
            try {
                try {
                    this.f[i] = new HashMap();
                } finally {
                    a();
                    if (z2) {
                        u();
                    }
                }
            } catch (IOException | UnsupportedOperationException e) {
                if (z2) {
                    Log.w("ExifInterface", "Invalid image: ExifInterface got an unsupported image format file (ExifInterface supports JPEG and some RAW image formats only) or a corrupted JPEG file to ExifInterface.", e);
                }
                a();
                if (z2) {
                    u();
                    return;
                }
                return;
            }
        }
        boolean z3 = this.e;
        if (!z3) {
            BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream, 5000);
            this.d = g(bufferedInputStream);
            inputStream = bufferedInputStream;
        }
        int i2 = this.d;
        if (i2 == 4 || i2 == 9 || i2 == 13 || i2 == 14) {
            b bVar = new b(inputStream);
            int i3 = this.d;
            if (i3 == 4) {
                f(bVar, 0, 0);
            } else if (i3 == 13) {
                i(bVar);
            } else if (i3 == 9) {
                j(bVar);
            } else if (i3 == 14) {
                o(bVar);
            }
        } else {
            g gVar = new g(inputStream);
            if (!z3) {
                int i4 = this.d;
                if (i4 == 12 || i4 == 15) {
                    e(gVar, i4);
                } else if (i4 == 7) {
                    h(gVar);
                } else if (i4 == 10) {
                    l(gVar);
                } else {
                    k(gVar);
                }
            } else if (!m(gVar)) {
                if (z2) {
                    return;
                } else {
                    return;
                }
            }
            gVar.d(this.p);
            F(gVar);
        }
        a();
        if (z2) {
            u();
        }
    }

    public final void t(g gVar) throws IOException {
        ByteOrder byteOrderV = v(gVar);
        this.h = byteOrderV;
        gVar.c = byteOrderV;
        int unsignedShort = gVar.readUnsignedShort();
        int i = this.d;
        if (i != 7 && i != 10 && unsignedShort != 42) {
            throw new IOException("Invalid start code: " + Integer.toHexString(unsignedShort));
        }
        int i2 = gVar.readInt();
        if (i2 < 8) {
            throw new IOException(android.support.v4.media.session.a.f(i2, "Invalid first Ifd offset: "));
        }
        int i3 = i2 - 8;
        if (i3 > 0) {
            gVar.a(i3);
        }
    }

    public final void u() {
        int i = 0;
        while (true) {
            HashMap[] mapArr = this.f;
            if (i >= mapArr.length) {
                return;
            }
            mapArr[i].size();
            for (Map.Entry entry : mapArr[i].entrySet()) {
                d dVar = (d) entry.getValue();
                dVar.toString();
                dVar.j(this.h);
            }
            i++;
        }
    }

    public final void w(int i, byte[] bArr) throws IOException {
        g gVar = new g(bArr);
        t(gVar);
        x(gVar, i);
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x018c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void x(androidx.exifinterface.media.g r27, int r28) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 643
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.exifinterface.media.h.x(androidx.exifinterface.media.g, int):void");
    }

    public final void y(String str) {
        for (int i = 0; i < V.length; i++) {
            this.f[i].remove(str);
        }
    }

    public final void z(int i, String str, String str2) {
        HashMap[] mapArr = this.f;
        if (mapArr[i].isEmpty() || mapArr[i].get(str) == null) {
            return;
        }
        HashMap map = mapArr[i];
        map.put(str2, (d) map.get(str));
        mapArr[i].remove(str);
    }

    public h(InputStream inputStream) throws IOException, ErrnoException {
        e[][] eVarArr = V;
        this.f = new HashMap[eVarArr.length];
        this.g = new HashSet(eVarArr.length);
        this.h = ByteOrder.BIG_ENDIAN;
        this.a = null;
        this.e = false;
        if (inputStream instanceof AssetManager.AssetInputStream) {
            this.c = (AssetManager.AssetInputStream) inputStream;
            this.b = null;
        } else if (inputStream instanceof FileInputStream) {
            FileInputStream fileInputStream = (FileInputStream) inputStream;
            try {
                Os.lseek(fileInputStream.getFD(), 0L, OsConstants.SEEK_CUR);
                this.c = null;
                this.b = fileInputStream.getFD();
            } catch (Exception unused) {
            }
        } else {
            this.c = null;
            this.b = null;
        }
        s(inputStream);
    }
}
