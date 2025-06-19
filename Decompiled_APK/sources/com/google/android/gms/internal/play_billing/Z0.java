package com.google.android.gms.internal.play_billing;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.attribution.RequestError;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.C2776wA;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.SortedSet;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class Z0 {
    public final /* synthetic */ int a;

    public /* synthetic */ Z0(int i) {
        this.a = i;
    }

    public static int C(byte[] bArr, int i, InterfaceC3799g1 interfaceC3799g1, C2776wA c2776wA) throws zzhr {
        C3790d1 c3790d1 = (C3790d1) interfaceC3799g1;
        int iH = H(bArr, i, c2776wA);
        int i2 = c2776wA.a + iH;
        while (iH < i2) {
            iH = H(bArr, iH, c2776wA);
            c3790d1.c(c2776wA.a);
        }
        if (iH == i2) {
            return iH;
        }
        throw new zzhr("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    public static String D(int i, int i2, String str) {
        if (i < 0) {
            return g("%s (%s) must not be negative", str, Integer.valueOf(i));
        }
        if (i2 >= 0) {
            return g("%s (%s) must not be greater than size (%s)", str, Integer.valueOf(i), Integer.valueOf(i2));
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
    }

    public static int F(int i, byte[] bArr, int i2, int i3, B1 b1, C2776wA c2776wA) throws zzhr {
        if ((i >>> 3) == 0) {
            throw new zzhr("Protocol message contained an invalid tag (zero).");
        }
        int i4 = i & 7;
        if (i4 == 0) {
            int iK = K(bArr, i2, c2776wA);
            b1.c(i, Long.valueOf(c2776wA.b));
            return iK;
        }
        if (i4 == 1) {
            b1.c(i, Long.valueOf(N(i2, bArr)));
            return i2 + 8;
        }
        if (i4 == 2) {
            int iH = H(bArr, i2, c2776wA);
            int i5 = c2776wA.a;
            if (i5 < 0) {
                throw new zzhr("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
            }
            if (i5 > bArr.length - iH) {
                throw new zzhr("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            if (i5 == 0) {
                b1.c(i, U0.c);
            } else {
                b1.c(i, U0.g(iH, bArr, i5));
            }
            return iH + i5;
        }
        if (i4 != 3) {
            if (i4 != 5) {
                throw new zzhr("Protocol message contained an invalid tag (zero).");
            }
            b1.c(i, Integer.valueOf(o(i2, bArr)));
            return i2 + 4;
        }
        int i6 = (i & (-8)) | 4;
        B1 b1B = B1.b();
        int i7 = c2776wA.d + 1;
        c2776wA.d = i7;
        if (i7 >= 100) {
            throw new zzhr("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i8 = 0;
        while (true) {
            if (i2 >= i3) {
                break;
            }
            int iH2 = H(bArr, i2, c2776wA);
            int i9 = c2776wA.a;
            if (i9 == i6) {
                i8 = i9;
                i2 = iH2;
                break;
            }
            i2 = F(i9, bArr, iH2, i3, b1B, c2776wA);
            i8 = i9;
        }
        c2776wA.d--;
        if (i2 > i3 || i8 != i6) {
            throw new zzhr("Failed to parse the message.");
        }
        b1.c(i, b1B);
        return i2;
    }

    public static int H(byte[] bArr, int i, C2776wA c2776wA) {
        int i2 = i + 1;
        byte b = bArr[i];
        if (b < 0) {
            return I(b, bArr, i2, c2776wA);
        }
        c2776wA.a = b;
        return i2;
    }

    public static int I(int i, byte[] bArr, int i2, C2776wA c2776wA) {
        byte b = bArr[i2];
        int i3 = i2 + 1;
        int i4 = i & 127;
        if (b >= 0) {
            c2776wA.a = i4 | (b << 7);
            return i3;
        }
        int i5 = i4 | ((b & Byte.MAX_VALUE) << 7);
        int i6 = i2 + 2;
        byte b2 = bArr[i3];
        if (b2 >= 0) {
            c2776wA.a = i5 | (b2 << 14);
            return i6;
        }
        int i7 = i5 | ((b2 & Byte.MAX_VALUE) << 14);
        int i8 = i2 + 3;
        byte b3 = bArr[i6];
        if (b3 >= 0) {
            c2776wA.a = i7 | (b3 << 21);
            return i8;
        }
        int i9 = i7 | ((b3 & Byte.MAX_VALUE) << 21);
        int i10 = i2 + 4;
        byte b4 = bArr[i8];
        if (b4 >= 0) {
            c2776wA.a = i9 | (b4 << 28);
            return i10;
        }
        int i11 = i9 | ((b4 & Byte.MAX_VALUE) << 28);
        while (true) {
            int i12 = i10 + 1;
            if (bArr[i10] >= 0) {
                c2776wA.a = i11;
                return i12;
            }
            i10 = i12;
        }
    }

    public static int J(int i, byte[] bArr, int i2, int i3, InterfaceC3799g1 interfaceC3799g1, C2776wA c2776wA) {
        C3790d1 c3790d1 = (C3790d1) interfaceC3799g1;
        int iH = H(bArr, i2, c2776wA);
        c3790d1.c(c2776wA.a);
        while (iH < i3) {
            int iH2 = H(bArr, iH, c2776wA);
            if (i != c2776wA.a) {
                break;
            }
            iH = H(bArr, iH2, c2776wA);
            c3790d1.c(c2776wA.a);
        }
        return iH;
    }

    public static int K(byte[] bArr, int i, C2776wA c2776wA) {
        long j = bArr[i];
        int i2 = i + 1;
        if (j >= 0) {
            c2776wA.b = j;
            return i2;
        }
        int i3 = i + 2;
        byte b = bArr[i2];
        long j2 = (j & 127) | ((b & Byte.MAX_VALUE) << 7);
        int i4 = 7;
        while (b < 0) {
            int i5 = i3 + 1;
            i4 += 7;
            j2 |= (r10 & Byte.MAX_VALUE) << i4;
            b = bArr[i3];
            i3 = i5;
        }
        c2776wA.b = j2;
        return i3;
    }

    public static int L(Object obj, InterfaceC3852y1 interfaceC3852y1, byte[] bArr, int i, int i2, int i3, C2776wA c2776wA) throws zzhr {
        C3831r1 c3831r1 = (C3831r1) interfaceC3852y1;
        int i4 = c2776wA.d + 1;
        c2776wA.d = i4;
        if (i4 >= 100) {
            throw new zzhr("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int iS = c3831r1.s(obj, bArr, i, i2, i3, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return iS;
    }

    public static int M(Object obj, InterfaceC3852y1 interfaceC3852y1, byte[] bArr, int i, int i2, C2776wA c2776wA) throws zzhr {
        int I = i + 1;
        int i3 = bArr[i];
        if (i3 < 0) {
            I = I(i3, bArr, I, c2776wA);
            i3 = c2776wA.a;
        }
        int i4 = I;
        if (i3 < 0 || i3 > i2 - i4) {
            throw new zzhr("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        int i5 = c2776wA.d + 1;
        c2776wA.d = i5;
        if (i5 >= 100) {
            throw new zzhr("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i6 = i4 + i3;
        interfaceC3852y1.e(obj, bArr, i4, i6, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return i6;
    }

    public static long N(int i, byte[] bArr) {
        return (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 6] & 255) << 48) | ((bArr[i + 7] & 255) << 56);
    }

    public static int c(int i) {
        return (int) (Integer.rotateLeft((int) (i * (-862048943)), 15) * 461845907);
    }

    public static int d(byte[] bArr, int i, C2776wA c2776wA) throws zzhr {
        int iH = H(bArr, i, c2776wA);
        int i2 = c2776wA.a;
        if (i2 < 0) {
            throw new zzhr("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        if (i2 > bArr.length - iH) {
            throw new zzhr("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        if (i2 == 0) {
            c2776wA.c = U0.c;
            return iH;
        }
        c2776wA.c = U0.g(iH, bArr, i2);
        return iH + i2;
    }

    public static String f(U0 u0) {
        StringBuilder sb = new StringBuilder(u0.c());
        for (int i = 0; i < u0.c(); i++) {
            byte bA = u0.a(i);
            if (bA == 34) {
                sb.append("\\\"");
            } else if (bA == 39) {
                sb.append("\\'");
            } else if (bA != 92) {
                switch (bA) {
                    case 7:
                        sb.append("\\a");
                        break;
                    case 8:
                        sb.append("\\b");
                        break;
                    case 9:
                        sb.append("\\t");
                        break;
                    case 10:
                        sb.append("\\n");
                        break;
                    case 11:
                        sb.append("\\v");
                        break;
                    case 12:
                        sb.append("\\f");
                        break;
                    case 13:
                        sb.append("\\r");
                        break;
                    default:
                        if (bA < 32 || bA > 126) {
                            sb.append('\\');
                            sb.append((char) (((bA >>> 6) & 3) + 48));
                            sb.append((char) (((bA >>> 3) & 7) + 48));
                            sb.append((char) ((bA & 7) + 48));
                            break;
                        } else {
                            sb.append((char) bA);
                            break;
                        }
                }
            } else {
                sb.append("\\\\");
            }
        }
        return sb.toString();
    }

    public static String g(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = android.support.v4.media.session.a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }

    public static void h(int i, int i2) {
        String strG;
        if (i < 0 || i >= i2) {
            if (i < 0) {
                strG = g("%s (%s) must not be negative", "index", Integer.valueOf(i));
            } else {
                if (i2 < 0) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "negative size: "));
                }
                strG = g("%s (%s) must be less than size (%s)", "index", Integer.valueOf(i), Integer.valueOf(i2));
            }
            throw new IndexOutOfBoundsException(strG);
        }
    }

    public static void i(int i, String str) {
        if (i >= 0) {
            return;
        }
        throw new IllegalArgumentException(str + " cannot be negative but was: " + i);
    }

    public static boolean k(Comparator comparator, Collection collection) {
        Object objComparator;
        comparator.getClass();
        collection.getClass();
        if (collection instanceof SortedSet) {
            objComparator = ((SortedSet) collection).comparator();
            if (objComparator == null) {
                objComparator = M.b;
            }
        } else {
            if (!(collection instanceof InterfaceC3780a0)) {
                return false;
            }
            objComparator = ((H) ((InterfaceC3780a0) collection)).c;
        }
        return comparator.equals(objComparator);
    }

    public static /* synthetic */ boolean l(AtomicReferenceFieldUpdater atomicReferenceFieldUpdater, AbstractC3816m0 abstractC3816m0, Object obj, Object obj2) {
        while (!atomicReferenceFieldUpdater.compareAndSet(abstractC3816m0, obj, obj2)) {
            if (atomicReferenceFieldUpdater.get(abstractC3816m0) != obj && atomicReferenceFieldUpdater.get(abstractC3816m0) != obj) {
                return false;
            }
        }
        return true;
    }

    public static /* synthetic */ boolean m(AtomicReferenceFieldUpdater atomicReferenceFieldUpdater, l2 l2Var, Object obj, Object obj2) {
        while (!atomicReferenceFieldUpdater.compareAndSet(l2Var, obj, obj2)) {
            if (atomicReferenceFieldUpdater.get(l2Var) != obj && atomicReferenceFieldUpdater.get(l2Var) != obj) {
                return false;
            }
        }
        return true;
    }

    public static int n(int i) {
        if (i == 90) {
            return 91;
        }
        if (i == 91) {
            return 92;
        }
        if (i == 93) {
            return 94;
        }
        if (i == 94) {
            return 95;
        }
        switch (i) {
            case 0:
                return 1;
            case 1:
                return 2;
            case 2:
                return 3;
            case 3:
                return 4;
            case 4:
                return 5;
            case 5:
                return 6;
            case 6:
                return 7;
            case 7:
                return 8;
            case 8:
                return 9;
            case 9:
                return 10;
            case 10:
                return 11;
            case 11:
                return 12;
            case 12:
                return 13;
            case 13:
                return 14;
            case 14:
                return 15;
            case 15:
                return 16;
            case 16:
                return 17;
            case 17:
                return 18;
            case 18:
                return 19;
            case 19:
                return 20;
            case 20:
                return 21;
            case 21:
                return 22;
            case EventType.WINDOW_STATE /* 22 */:
                return 23;
            case EventType.AUDIO /* 23 */:
                return 24;
            case EventType.VIDEO /* 24 */:
                return 25;
            case EventType.SUBS /* 25 */:
                return 26;
            case EventType.CDN /* 26 */:
                return 27;
            case 27:
                return 28;
            case 28:
                return 29;
            case 29:
                return 30;
            case 30:
                return 31;
            case 31:
                return 32;
            case 32:
                return 33;
            case 33:
                return 34;
            case 34:
                return 35;
            case 35:
                return 36;
            case 36:
                return 37;
            case 37:
                return 38;
            case 38:
                return 39;
            case 39:
                return 40;
            case RequestError.NETWORK_FAILURE /* 40 */:
                return 41;
            case RequestError.NO_DEV_KEY /* 41 */:
                return 42;
            case 42:
                return 43;
            case 43:
                return 44;
            case 44:
                return 45;
            case 45:
                return 46;
            case 46:
                return 47;
            case 47:
                return 48;
            case 48:
                return 49;
            case 49:
                return 50;
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                return 51;
            case 51:
                return 52;
            case 52:
                return 53;
            case 53:
                return 54;
            case 54:
                return 55;
            case 55:
                return 56;
            case 56:
                return 57;
            case 57:
                return 58;
            case 58:
                return 59;
            case 59:
                return 60;
            case 60:
                return 61;
            case 61:
                return 62;
            case 62:
                return 63;
            case 63:
                return 64;
            case 64:
                return 65;
            case 65:
                return 66;
            case 66:
                return 67;
            case 67:
                return 68;
            case 68:
                return 69;
            case 69:
                return 70;
            case 70:
                return 71;
            case 71:
                return 72;
            case 72:
                return 73;
            case 73:
                return 74;
            case 74:
                return 75;
            case 75:
                return 76;
            case 76:
                return 77;
            case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                return 78;
            case 78:
                return 79;
            case 79:
                return 80;
            default:
                switch (i) {
                    case 96:
                        return 97;
                    case 97:
                        return 98;
                    case 98:
                        return 99;
                    case 99:
                        return 100;
                    case 100:
                        return 101;
                    case 101:
                        return 102;
                    case 102:
                        return 103;
                    case 103:
                        return 104;
                    case 104:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION /* 109 */:
                        return OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED;
                    case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED /* 110 */:
                        return 111;
                    case 111:
                        return ContentType.LONG_FORM_ON_DEMAND;
                    case ContentType.LONG_FORM_ON_DEMAND /* 112 */:
                        return ContentType.LIVE;
                    case ContentType.LIVE /* 113 */:
                        return 114;
                    case 114:
                        return 115;
                    case 115:
                        return 116;
                    case 116:
                        return 117;
                    case 117:
                        return 118;
                    case 118:
                        return 119;
                    case 119:
                        return 120;
                    case 120:
                        return ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND;
                    case ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND /* 121 */:
                        return ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND;
                    default:
                        return 0;
                }
        }
    }

    public static int o(int i, byte[] bArr) {
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return ((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16);
    }

    public static W0 q() {
        String strI;
        ClassLoader classLoader = Z0.class.getClassLoader();
        if (W0.class.equals(W0.class)) {
            strI = "com.google.protobuf.BlazeGeneratedExtensionRegistryLiteLoader";
        } else {
            if (!W0.class.getPackage().equals(Z0.class.getPackage())) {
                throw new IllegalArgumentException(W0.class.getName());
            }
            strI = androidx.compose.ui.node.B.i(W0.class.getPackage().getName(), ".BlazeGenerated", W0.class.getSimpleName(), "Loader");
        }
        try {
            try {
                try {
                    android.support.v4.media.session.a.A(Class.forName(strI, true, classLoader).getConstructor(null).newInstance(null));
                    throw null;
                } catch (InstantiationException e) {
                    throw new IllegalStateException(e);
                } catch (InvocationTargetException e2) {
                    throw new IllegalStateException(e2);
                }
            } catch (IllegalAccessException e3) {
                throw new IllegalStateException(e3);
            } catch (NoSuchMethodException e4) {
                throw new IllegalStateException(e4);
            }
        } catch (ClassNotFoundException unused) {
            try {
                Iterator it2 = Arrays.asList(new Z0[0]).iterator();
                ArrayList arrayList = new ArrayList();
                while (it2.hasNext()) {
                    try {
                        if (it2.next() == null) {
                            throw null;
                        }
                        throw new ClassCastException();
                    } catch (ServiceConfigurationError e5) {
                        Logger.getLogger(V0.class.getName()).logp(Level.SEVERE, "com.google.protobuf.GeneratedExtensionRegistryLoader", "load", "Unable to load ".concat(W0.class.getSimpleName()), (Throwable) e5);
                    }
                }
                if (arrayList.size() == 1) {
                    return (W0) arrayList.get(0);
                }
                if (arrayList.size() == 0) {
                    return null;
                }
                try {
                    return (W0) W0.class.getMethod("combine", Collection.class).invoke(null, arrayList);
                } catch (IllegalAccessException e6) {
                    throw new IllegalStateException(e6);
                } catch (NoSuchMethodException e7) {
                    throw new IllegalStateException(e7);
                } catch (InvocationTargetException e8) {
                    throw new IllegalStateException(e8);
                }
            } catch (Throwable th) {
                throw new ServiceConfigurationError(th.getMessage(), th);
            }
        }
    }

    public static void r(int i, int i2) {
        if (i < 0 || i > i2) {
            throw new IndexOutOfBoundsException(D(i, i2, "index"));
        }
    }

    public static int x(InterfaceC3852y1 interfaceC3852y1, int i, byte[] bArr, int i2, int i3, InterfaceC3799g1 interfaceC3799g1, C2776wA c2776wA) throws zzhr {
        AbstractC3787c1 abstractC3787c1Zze = interfaceC3852y1.zze();
        InterfaceC3852y1 interfaceC3852y12 = interfaceC3852y1;
        byte[] bArr2 = bArr;
        int i4 = i3;
        C2776wA c2776wA2 = c2776wA;
        int iM = M(abstractC3787c1Zze, interfaceC3852y12, bArr2, i2, i4, c2776wA2);
        interfaceC3852y12.a(abstractC3787c1Zze);
        c2776wA2.c = abstractC3787c1Zze;
        interfaceC3799g1.add(abstractC3787c1Zze);
        while (iM < i4) {
            C2776wA c2776wA3 = c2776wA2;
            int i5 = i4;
            int iH = H(bArr2, iM, c2776wA3);
            if (i != c2776wA3.a) {
                break;
            }
            byte[] bArr3 = bArr2;
            InterfaceC3852y1 interfaceC3852y13 = interfaceC3852y12;
            AbstractC3787c1 abstractC3787c1Zze2 = interfaceC3852y13.zze();
            iM = M(abstractC3787c1Zze2, interfaceC3852y13, bArr3, iH, i5, c2776wA3);
            interfaceC3852y12 = interfaceC3852y13;
            bArr2 = bArr3;
            i4 = i5;
            c2776wA2 = c2776wA3;
            interfaceC3852y12.a(abstractC3787c1Zze2);
            c2776wA2.c = abstractC3787c1Zze2;
            interfaceC3799g1.add(abstractC3787c1Zze2);
        }
        return iM;
    }

    public static void y(int i, int i2, int i3) {
        if (i < 0 || i2 < i || i2 > i3) {
            throw new IndexOutOfBoundsException((i < 0 || i > i3) ? D(i, i3, "start index") : (i2 < 0 || i2 > i3) ? D(i2, i3, "end index") : g("end index (%s) must not be less than start index (%s)", Integer.valueOf(i2), Integer.valueOf(i)));
        }
    }

    public static boolean z(byte b) {
        return b > -65;
    }

    public abstract boolean A(AbstractC3816m0 abstractC3816m0, C3792e0 c3792e0, C3792e0 c3792e02);

    public abstract boolean B(l2 l2Var, k2 k2Var, k2 k2Var2);

    public abstract boolean E(AbstractC3816m0 abstractC3816m0, Object obj, Object obj2);

    public abstract boolean G(AbstractC3816m0 abstractC3816m0, C3813l0 c3813l0, C3813l0 c3813l02);

    public abstract C3792e0 e(AbstractC3816m0 abstractC3816m0);

    public abstract void j(k2 k2Var, k2 k2Var2);

    public abstract C3813l0 p(AbstractC3816m0 abstractC3816m0);

    public abstract void s(k2 k2Var, Thread thread);

    public abstract void t(C3813l0 c3813l0, C3813l0 c3813l02);

    public String toString() {
        switch (this.a) {
            case 4:
                return ((A0) this).b.toString();
            default:
                return super.toString();
        }
    }

    public abstract boolean u(l2 l2Var, A1 a1, A1 a12);

    public abstract void v(C3813l0 c3813l0, Thread thread);

    public abstract boolean w(l2 l2Var, Object obj, Object obj2);
}
