package androidx.constraintlayout.widget;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.content.res.XmlResourceParser;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseIntArray;
import android.util.Xml;
import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.attribution.RequestError;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public final class o {
    public static final int[] e = {0, 4, 8};
    public static final SparseIntArray f;
    public static final SparseIntArray g;
    public final int a = 0;
    public final HashMap b = new HashMap();
    public final boolean c = true;
    public final HashMap d = new HashMap();

    static {
        SparseIntArray sparseIntArray = new SparseIntArray();
        f = sparseIntArray;
        SparseIntArray sparseIntArray2 = new SparseIntArray();
        g = sparseIntArray2;
        sparseIntArray.append(82, 25);
        sparseIntArray.append(83, 26);
        sparseIntArray.append(85, 29);
        sparseIntArray.append(86, 30);
        sparseIntArray.append(92, 36);
        sparseIntArray.append(91, 35);
        sparseIntArray.append(63, 4);
        sparseIntArray.append(62, 3);
        sparseIntArray.append(58, 1);
        sparseIntArray.append(60, 91);
        sparseIntArray.append(59, 92);
        sparseIntArray.append(101, 6);
        sparseIntArray.append(102, 7);
        sparseIntArray.append(70, 17);
        sparseIntArray.append(71, 18);
        sparseIntArray.append(72, 19);
        sparseIntArray.append(54, 99);
        sparseIntArray.append(0, 27);
        sparseIntArray.append(87, 32);
        sparseIntArray.append(88, 33);
        sparseIntArray.append(69, 10);
        sparseIntArray.append(68, 9);
        sparseIntArray.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF, 13);
        sparseIntArray.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION, 16);
        sparseIntArray.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 14);
        sparseIntArray.append(104, 11);
        sparseIntArray.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, 15);
        sparseIntArray.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED, 12);
        sparseIntArray.append(95, 40);
        sparseIntArray.append(80, 39);
        sparseIntArray.append(79, 41);
        sparseIntArray.append(94, 42);
        sparseIntArray.append(78, 20);
        sparseIntArray.append(93, 37);
        sparseIntArray.append(67, 5);
        sparseIntArray.append(81, 87);
        sparseIntArray.append(90, 87);
        sparseIntArray.append(84, 87);
        sparseIntArray.append(61, 87);
        sparseIntArray.append(57, 87);
        sparseIntArray.append(5, 24);
        sparseIntArray.append(7, 28);
        sparseIntArray.append(23, 31);
        sparseIntArray.append(24, 8);
        sparseIntArray.append(6, 34);
        sparseIntArray.append(8, 2);
        sparseIntArray.append(3, 23);
        sparseIntArray.append(4, 21);
        sparseIntArray.append(96, 95);
        sparseIntArray.append(73, 96);
        sparseIntArray.append(2, 22);
        sparseIntArray.append(13, 43);
        sparseIntArray.append(26, 44);
        sparseIntArray.append(21, 45);
        sparseIntArray.append(22, 46);
        sparseIntArray.append(20, 60);
        sparseIntArray.append(18, 47);
        sparseIntArray.append(19, 48);
        sparseIntArray.append(14, 49);
        sparseIntArray.append(15, 50);
        sparseIntArray.append(16, 51);
        sparseIntArray.append(17, 52);
        sparseIntArray.append(25, 53);
        sparseIntArray.append(97, 54);
        sparseIntArray.append(74, 55);
        sparseIntArray.append(98, 56);
        sparseIntArray.append(75, 57);
        sparseIntArray.append(99, 58);
        sparseIntArray.append(76, 59);
        sparseIntArray.append(64, 61);
        sparseIntArray.append(66, 62);
        sparseIntArray.append(65, 63);
        sparseIntArray.append(28, 64);
        sparseIntArray.append(ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND, 65);
        sparseIntArray.append(35, 66);
        sparseIntArray.append(ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND, 67);
        sparseIntArray.append(ContentType.LIVE, 79);
        sparseIntArray.append(1, 38);
        sparseIntArray.append(ContentType.LONG_FORM_ON_DEMAND, 68);
        sparseIntArray.append(100, 69);
        sparseIntArray.append(77, 70);
        sparseIntArray.append(111, 97);
        sparseIntArray.append(32, 71);
        sparseIntArray.append(30, 72);
        sparseIntArray.append(31, 73);
        sparseIntArray.append(33, 74);
        sparseIntArray.append(29, 75);
        sparseIntArray.append(114, 76);
        sparseIntArray.append(89, 77);
        sparseIntArray.append(ContentType.USER_GENERATED_LIVE, 78);
        sparseIntArray.append(56, 80);
        sparseIntArray.append(55, 81);
        sparseIntArray.append(116, 82);
        sparseIntArray.append(120, 83);
        sparseIntArray.append(119, 84);
        sparseIntArray.append(118, 85);
        sparseIntArray.append(117, 86);
        sparseIntArray2.append(85, 6);
        sparseIntArray2.append(85, 7);
        sparseIntArray2.append(0, 27);
        sparseIntArray2.append(89, 13);
        sparseIntArray2.append(92, 16);
        sparseIntArray2.append(90, 14);
        sparseIntArray2.append(87, 11);
        sparseIntArray2.append(91, 15);
        sparseIntArray2.append(88, 12);
        sparseIntArray2.append(78, 40);
        sparseIntArray2.append(71, 39);
        sparseIntArray2.append(70, 41);
        sparseIntArray2.append(77, 42);
        sparseIntArray2.append(69, 20);
        sparseIntArray2.append(76, 37);
        sparseIntArray2.append(60, 5);
        sparseIntArray2.append(72, 87);
        sparseIntArray2.append(75, 87);
        sparseIntArray2.append(73, 87);
        sparseIntArray2.append(57, 87);
        sparseIntArray2.append(56, 87);
        sparseIntArray2.append(5, 24);
        sparseIntArray2.append(7, 28);
        sparseIntArray2.append(23, 31);
        sparseIntArray2.append(24, 8);
        sparseIntArray2.append(6, 34);
        sparseIntArray2.append(8, 2);
        sparseIntArray2.append(3, 23);
        sparseIntArray2.append(4, 21);
        sparseIntArray2.append(79, 95);
        sparseIntArray2.append(64, 96);
        sparseIntArray2.append(2, 22);
        sparseIntArray2.append(13, 43);
        sparseIntArray2.append(26, 44);
        sparseIntArray2.append(21, 45);
        sparseIntArray2.append(22, 46);
        sparseIntArray2.append(20, 60);
        sparseIntArray2.append(18, 47);
        sparseIntArray2.append(19, 48);
        sparseIntArray2.append(14, 49);
        sparseIntArray2.append(15, 50);
        sparseIntArray2.append(16, 51);
        sparseIntArray2.append(17, 52);
        sparseIntArray2.append(25, 53);
        sparseIntArray2.append(80, 54);
        sparseIntArray2.append(65, 55);
        sparseIntArray2.append(81, 56);
        sparseIntArray2.append(66, 57);
        sparseIntArray2.append(82, 58);
        sparseIntArray2.append(67, 59);
        sparseIntArray2.append(59, 62);
        sparseIntArray2.append(58, 63);
        sparseIntArray2.append(28, 64);
        sparseIntArray2.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED, 65);
        sparseIntArray2.append(34, 66);
        sparseIntArray2.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF, 67);
        sparseIntArray2.append(96, 79);
        sparseIntArray2.append(1, 38);
        sparseIntArray2.append(97, 98);
        sparseIntArray2.append(95, 68);
        sparseIntArray2.append(83, 69);
        sparseIntArray2.append(68, 70);
        sparseIntArray2.append(32, 71);
        sparseIntArray2.append(30, 72);
        sparseIntArray2.append(31, 73);
        sparseIntArray2.append(33, 74);
        sparseIntArray2.append(29, 75);
        sparseIntArray2.append(98, 76);
        sparseIntArray2.append(74, 77);
        sparseIntArray2.append(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED, 78);
        sparseIntArray2.append(55, 80);
        sparseIntArray2.append(54, 81);
        sparseIntArray2.append(100, 82);
        sparseIntArray2.append(104, 83);
        sparseIntArray2.append(103, 84);
        sparseIntArray2.append(102, 85);
        sparseIntArray2.append(101, 86);
        sparseIntArray2.append(94, 97);
    }

    public static int[] f(a aVar, String str) throws IllegalAccessException, IllegalArgumentException {
        int iIntValue;
        String[] strArrSplit = str.split(",");
        Context context = aVar.getContext();
        int[] iArr = new int[strArrSplit.length];
        int i = 0;
        int i2 = 0;
        while (i < strArrSplit.length) {
            String strTrim = strArrSplit[i].trim();
            Object obj = null;
            try {
                iIntValue = t.class.getField(strTrim).getInt(null);
            } catch (Exception unused) {
                iIntValue = 0;
            }
            if (iIntValue == 0) {
                iIntValue = context.getResources().getIdentifier(strTrim, "id", context.getPackageName());
            }
            if (iIntValue == 0 && aVar.isInEditMode() && (aVar.getParent() instanceof ConstraintLayout)) {
                ConstraintLayout constraintLayout = (ConstraintLayout) aVar.getParent();
                if (strTrim != null) {
                    HashMap map = constraintLayout.m;
                    if (map != null && map.containsKey(strTrim)) {
                        obj = constraintLayout.m.get(strTrim);
                    }
                } else {
                    constraintLayout.getClass();
                }
                if (obj != null && (obj instanceof Integer)) {
                    iIntValue = ((Integer) obj).intValue();
                }
            }
            iArr[i2] = iIntValue;
            i++;
            i2++;
        }
        return i2 != strArrSplit.length ? Arrays.copyOf(iArr, i2) : iArr;
    }

    public static j g(Context context, AttributeSet attributeSet, boolean z) {
        char c;
        j jVar = new j();
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, z ? u.c : u.a);
        if (z) {
            int indexCount = typedArrayObtainStyledAttributes.getIndexCount();
            i iVar = new i();
            iVar.a = new int[10];
            iVar.b = new int[10];
            iVar.c = 0;
            iVar.d = new int[10];
            iVar.e = new float[10];
            iVar.f = 0;
            iVar.g = new int[5];
            iVar.h = new String[5];
            iVar.i = 0;
            iVar.j = new int[4];
            iVar.k = new boolean[4];
            iVar.l = 0;
            jVar.g = iVar;
            l lVar = jVar.c;
            lVar.a = false;
            k kVar = jVar.d;
            kVar.b = false;
            m mVar = jVar.b;
            mVar.a = false;
            n nVar = jVar.e;
            nVar.a = false;
            for (int i = 0; i < indexCount; i++) {
                int index = typedArrayObtainStyledAttributes.getIndex(i);
                int i2 = g.get(index);
                SparseIntArray sparseIntArray = f;
                switch (i2) {
                    case 2:
                        c = 5;
                        iVar.b(2, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.J));
                        break;
                    case 3:
                    case 4:
                    case 9:
                    case 10:
                    case EventType.SUBS /* 25 */:
                    case EventType.CDN /* 26 */:
                    case 29:
                    case 30:
                    case 32:
                    case 33:
                    case 35:
                    case 36:
                    case 61:
                    case 88:
                    case 89:
                    case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                    case 91:
                    case 92:
                    default:
                        Log.w("ConstraintSet", "Unknown attribute 0x" + Integer.toHexString(index) + "   " + sparseIntArray.get(index));
                        c = 5;
                        break;
                    case 5:
                        c = 5;
                        iVar.c(5, typedArrayObtainStyledAttributes.getString(index));
                        break;
                    case 6:
                        iVar.b(6, typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, kVar.D));
                        c = 5;
                        break;
                    case 7:
                        iVar.b(7, typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, kVar.E));
                        c = 5;
                        break;
                    case 8:
                        iVar.b(8, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.K));
                        c = 5;
                        break;
                    case 11:
                        iVar.b(11, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.Q));
                        c = 5;
                        break;
                    case 12:
                        iVar.b(12, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.R));
                        c = 5;
                        break;
                    case 13:
                        iVar.b(13, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.N));
                        c = 5;
                        break;
                    case 14:
                        iVar.b(14, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.P));
                        c = 5;
                        break;
                    case 15:
                        iVar.b(15, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.S));
                        c = 5;
                        break;
                    case 16:
                        iVar.b(16, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.O));
                        c = 5;
                        break;
                    case 17:
                        iVar.b(17, typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, kVar.e));
                        c = 5;
                        break;
                    case 18:
                        iVar.b(18, typedArrayObtainStyledAttributes.getDimensionPixelOffset(index, kVar.f));
                        c = 5;
                        break;
                    case 19:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.g), 19);
                        c = 5;
                        break;
                    case 20:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.x), 20);
                        c = 5;
                        break;
                    case 21:
                        iVar.b(21, typedArrayObtainStyledAttributes.getLayoutDimension(index, kVar.d));
                        c = 5;
                        break;
                    case EventType.WINDOW_STATE /* 22 */:
                        iVar.b(22, e[typedArrayObtainStyledAttributes.getInt(index, mVar.b)]);
                        c = 5;
                        break;
                    case EventType.AUDIO /* 23 */:
                        iVar.b(23, typedArrayObtainStyledAttributes.getLayoutDimension(index, kVar.c));
                        c = 5;
                        break;
                    case EventType.VIDEO /* 24 */:
                        iVar.b(24, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.G));
                        c = 5;
                        break;
                    case 27:
                        iVar.b(27, typedArrayObtainStyledAttributes.getInt(index, kVar.F));
                        c = 5;
                        break;
                    case 28:
                        iVar.b(28, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.H));
                        c = 5;
                        break;
                    case 31:
                        iVar.b(31, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.L));
                        c = 5;
                        break;
                    case 34:
                        iVar.b(34, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.I));
                        c = 5;
                        break;
                    case 37:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.y), 37);
                        c = 5;
                        break;
                    case 38:
                        int resourceId = typedArrayObtainStyledAttributes.getResourceId(index, jVar.a);
                        jVar.a = resourceId;
                        iVar.b(38, resourceId);
                        c = 5;
                        break;
                    case 39:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.V), 39);
                        c = 5;
                        break;
                    case RequestError.NETWORK_FAILURE /* 40 */:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.U), 40);
                        c = 5;
                        break;
                    case RequestError.NO_DEV_KEY /* 41 */:
                        iVar.b(41, typedArrayObtainStyledAttributes.getInt(index, kVar.W));
                        c = 5;
                        break;
                    case 42:
                        iVar.b(42, typedArrayObtainStyledAttributes.getInt(index, kVar.X));
                        c = 5;
                        break;
                    case 43:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, mVar.d), 43);
                        c = 5;
                        break;
                    case 44:
                        iVar.d(44, true);
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.n), 44);
                        c = 5;
                        break;
                    case 45:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, nVar.c), 45);
                        c = 5;
                        break;
                    case 46:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, nVar.d), 46);
                        c = 5;
                        break;
                    case 47:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, nVar.e), 47);
                        c = 5;
                        break;
                    case 48:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, nVar.f), 48);
                        c = 5;
                        break;
                    case 49:
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.g), 49);
                        c = 5;
                        break;
                    case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.h), 50);
                        c = 5;
                        break;
                    case 51:
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.j), 51);
                        c = 5;
                        break;
                    case 52:
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.k), 52);
                        c = 5;
                        break;
                    case 53:
                        iVar.a(typedArrayObtainStyledAttributes.getDimension(index, nVar.l), 53);
                        c = 5;
                        break;
                    case 54:
                        iVar.b(54, typedArrayObtainStyledAttributes.getInt(index, kVar.Y));
                        c = 5;
                        break;
                    case 55:
                        iVar.b(55, typedArrayObtainStyledAttributes.getInt(index, kVar.Z));
                        c = 5;
                        break;
                    case 56:
                        iVar.b(56, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.a0));
                        c = 5;
                        break;
                    case 57:
                        iVar.b(57, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.b0));
                        c = 5;
                        break;
                    case 58:
                        iVar.b(58, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.c0));
                        c = 5;
                        break;
                    case 59:
                        iVar.b(59, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.d0));
                        c = 5;
                        break;
                    case 60:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, nVar.b), 60);
                        c = 5;
                        break;
                    case 62:
                        iVar.b(62, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.B));
                        c = 5;
                        break;
                    case 63:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, kVar.C), 63);
                        c = 5;
                        break;
                    case 64:
                        iVar.b(64, j(typedArrayObtainStyledAttributes, index, lVar.b));
                        c = 5;
                        break;
                    case 65:
                        if (typedArrayObtainStyledAttributes.peekValue(index).type == 3) {
                            iVar.c(65, typedArrayObtainStyledAttributes.getString(index));
                        } else {
                            iVar.c(65, androidx.constraintlayout.core.motion.utils.e.d[typedArrayObtainStyledAttributes.getInteger(index, 0)]);
                        }
                        c = 5;
                        break;
                    case 66:
                        iVar.b(66, typedArrayObtainStyledAttributes.getInt(index, 0));
                        c = 5;
                        break;
                    case 67:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, lVar.h), 67);
                        c = 5;
                        break;
                    case 68:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, mVar.e), 68);
                        c = 5;
                        break;
                    case 69:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, 1.0f), 69);
                        c = 5;
                        break;
                    case 70:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, 1.0f), 70);
                        c = 5;
                        break;
                    case 71:
                        Log.e("ConstraintSet", "CURRENTLY UNSUPPORTED");
                        c = 5;
                        break;
                    case 72:
                        iVar.b(72, typedArrayObtainStyledAttributes.getInt(index, kVar.g0));
                        c = 5;
                        break;
                    case 73:
                        iVar.b(73, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.h0));
                        c = 5;
                        break;
                    case 74:
                        iVar.c(74, typedArrayObtainStyledAttributes.getString(index));
                        c = 5;
                        break;
                    case 75:
                        iVar.d(75, typedArrayObtainStyledAttributes.getBoolean(index, kVar.o0));
                        c = 5;
                        break;
                    case 76:
                        iVar.b(76, typedArrayObtainStyledAttributes.getInt(index, lVar.e));
                        c = 5;
                        break;
                    case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                        iVar.c(77, typedArrayObtainStyledAttributes.getString(index));
                        c = 5;
                        break;
                    case 78:
                        iVar.b(78, typedArrayObtainStyledAttributes.getInt(index, mVar.c));
                        c = 5;
                        break;
                    case 79:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, lVar.g), 79);
                        c = 5;
                        break;
                    case 80:
                        iVar.d(80, typedArrayObtainStyledAttributes.getBoolean(index, kVar.m0));
                        c = 5;
                        break;
                    case 81:
                        iVar.d(81, typedArrayObtainStyledAttributes.getBoolean(index, kVar.n0));
                        c = 5;
                        break;
                    case 82:
                        iVar.b(82, typedArrayObtainStyledAttributes.getInteger(index, lVar.c));
                        c = 5;
                        break;
                    case 83:
                        iVar.b(83, j(typedArrayObtainStyledAttributes, index, nVar.i));
                        c = 5;
                        break;
                    case 84:
                        iVar.b(84, typedArrayObtainStyledAttributes.getInteger(index, lVar.j));
                        c = 5;
                        break;
                    case 85:
                        iVar.a(typedArrayObtainStyledAttributes.getFloat(index, lVar.i), 85);
                        c = 5;
                        break;
                    case 86:
                        int i3 = typedArrayObtainStyledAttributes.peekValue(index).type;
                        if (i3 == 1) {
                            int resourceId2 = typedArrayObtainStyledAttributes.getResourceId(index, -1);
                            lVar.m = resourceId2;
                            iVar.b(89, resourceId2);
                            if (lVar.m != -1) {
                                lVar.l = -2;
                                iVar.b(88, -2);
                            }
                        } else if (i3 == 3) {
                            String string = typedArrayObtainStyledAttributes.getString(index);
                            lVar.k = string;
                            iVar.c(90, string);
                            if (lVar.k.indexOf("/") > 0) {
                                int resourceId3 = typedArrayObtainStyledAttributes.getResourceId(index, -1);
                                lVar.m = resourceId3;
                                iVar.b(89, resourceId3);
                                lVar.l = -2;
                                iVar.b(88, -2);
                            } else {
                                lVar.l = -1;
                                iVar.b(88, -1);
                            }
                        } else {
                            int integer = typedArrayObtainStyledAttributes.getInteger(index, lVar.m);
                            lVar.l = integer;
                            iVar.b(88, integer);
                        }
                        c = 5;
                        break;
                    case 87:
                        Log.w("ConstraintSet", "unused attribute 0x" + Integer.toHexString(index) + "   " + sparseIntArray.get(index));
                        c = 5;
                        break;
                    case 93:
                        iVar.b(93, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.M));
                        c = 5;
                        break;
                    case 94:
                        iVar.b(94, typedArrayObtainStyledAttributes.getDimensionPixelSize(index, kVar.T));
                        c = 5;
                        break;
                    case 95:
                        k(iVar, typedArrayObtainStyledAttributes, index, 0);
                        c = 5;
                        break;
                    case 96:
                        k(iVar, typedArrayObtainStyledAttributes, index, 1);
                        c = 5;
                        break;
                    case 97:
                        iVar.b(97, typedArrayObtainStyledAttributes.getInt(index, kVar.p0));
                        c = 5;
                        break;
                    case 98:
                        if (androidx.constraintlayout.motion.widget.r.J1) {
                            int resourceId4 = typedArrayObtainStyledAttributes.getResourceId(index, jVar.a);
                            jVar.a = resourceId4;
                            if (resourceId4 == -1) {
                                typedArrayObtainStyledAttributes.getString(index);
                            }
                        } else if (typedArrayObtainStyledAttributes.peekValue(index).type == 3) {
                            typedArrayObtainStyledAttributes.getString(index);
                        } else {
                            jVar.a = typedArrayObtainStyledAttributes.getResourceId(index, jVar.a);
                        }
                        c = 5;
                        break;
                    case 99:
                        iVar.d(99, typedArrayObtainStyledAttributes.getBoolean(index, kVar.h));
                        c = 5;
                        break;
                }
            }
        } else {
            int indexCount2 = typedArrayObtainStyledAttributes.getIndexCount();
            int i4 = 0;
            while (true) {
                k kVar2 = jVar.d;
                if (i4 < indexCount2) {
                    int index2 = typedArrayObtainStyledAttributes.getIndex(i4);
                    m mVar2 = jVar.b;
                    n nVar2 = jVar.e;
                    l lVar2 = jVar.c;
                    if (index2 != 1 && 23 != index2 && 24 != index2) {
                        lVar2.a = true;
                        kVar2.b = true;
                        mVar2.a = true;
                        nVar2.a = true;
                    }
                    SparseIntArray sparseIntArray2 = f;
                    switch (sparseIntArray2.get(index2)) {
                        case 1:
                            kVar2.q = j(typedArrayObtainStyledAttributes, index2, kVar2.q);
                            break;
                        case 2:
                            kVar2.J = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.J);
                            break;
                        case 3:
                            kVar2.p = j(typedArrayObtainStyledAttributes, index2, kVar2.p);
                            break;
                        case 4:
                            kVar2.o = j(typedArrayObtainStyledAttributes, index2, kVar2.o);
                            break;
                        case 5:
                            kVar2.z = typedArrayObtainStyledAttributes.getString(index2);
                            break;
                        case 6:
                            kVar2.D = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index2, kVar2.D);
                            break;
                        case 7:
                            kVar2.E = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index2, kVar2.E);
                            break;
                        case 8:
                            kVar2.K = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.K);
                            break;
                        case 9:
                            kVar2.w = j(typedArrayObtainStyledAttributes, index2, kVar2.w);
                            break;
                        case 10:
                            kVar2.v = j(typedArrayObtainStyledAttributes, index2, kVar2.v);
                            break;
                        case 11:
                            kVar2.Q = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.Q);
                            break;
                        case 12:
                            kVar2.R = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.R);
                            break;
                        case 13:
                            kVar2.N = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.N);
                            break;
                        case 14:
                            kVar2.P = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.P);
                            break;
                        case 15:
                            kVar2.S = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.S);
                            break;
                        case 16:
                            kVar2.O = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.O);
                            break;
                        case 17:
                            kVar2.e = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index2, kVar2.e);
                            break;
                        case 18:
                            kVar2.f = typedArrayObtainStyledAttributes.getDimensionPixelOffset(index2, kVar2.f);
                            break;
                        case 19:
                            kVar2.g = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.g);
                            break;
                        case 20:
                            kVar2.x = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.x);
                            break;
                        case 21:
                            kVar2.d = typedArrayObtainStyledAttributes.getLayoutDimension(index2, kVar2.d);
                            break;
                        case EventType.WINDOW_STATE /* 22 */:
                            int i5 = typedArrayObtainStyledAttributes.getInt(index2, mVar2.b);
                            mVar2.b = i5;
                            mVar2.b = e[i5];
                            break;
                        case EventType.AUDIO /* 23 */:
                            kVar2.c = typedArrayObtainStyledAttributes.getLayoutDimension(index2, kVar2.c);
                            break;
                        case EventType.VIDEO /* 24 */:
                            kVar2.G = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.G);
                            break;
                        case EventType.SUBS /* 25 */:
                            kVar2.i = j(typedArrayObtainStyledAttributes, index2, kVar2.i);
                            break;
                        case EventType.CDN /* 26 */:
                            kVar2.j = j(typedArrayObtainStyledAttributes, index2, kVar2.j);
                            break;
                        case 27:
                            kVar2.F = typedArrayObtainStyledAttributes.getInt(index2, kVar2.F);
                            break;
                        case 28:
                            kVar2.H = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.H);
                            break;
                        case 29:
                            kVar2.k = j(typedArrayObtainStyledAttributes, index2, kVar2.k);
                            break;
                        case 30:
                            kVar2.l = j(typedArrayObtainStyledAttributes, index2, kVar2.l);
                            break;
                        case 31:
                            kVar2.L = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.L);
                            break;
                        case 32:
                            kVar2.t = j(typedArrayObtainStyledAttributes, index2, kVar2.t);
                            break;
                        case 33:
                            kVar2.u = j(typedArrayObtainStyledAttributes, index2, kVar2.u);
                            break;
                        case 34:
                            kVar2.I = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.I);
                            break;
                        case 35:
                            kVar2.n = j(typedArrayObtainStyledAttributes, index2, kVar2.n);
                            break;
                        case 36:
                            kVar2.m = j(typedArrayObtainStyledAttributes, index2, kVar2.m);
                            break;
                        case 37:
                            kVar2.y = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.y);
                            break;
                        case 38:
                            jVar.a = typedArrayObtainStyledAttributes.getResourceId(index2, jVar.a);
                            break;
                        case 39:
                            kVar2.V = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.V);
                            break;
                        case RequestError.NETWORK_FAILURE /* 40 */:
                            kVar2.U = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.U);
                            break;
                        case RequestError.NO_DEV_KEY /* 41 */:
                            kVar2.W = typedArrayObtainStyledAttributes.getInt(index2, kVar2.W);
                            break;
                        case 42:
                            kVar2.X = typedArrayObtainStyledAttributes.getInt(index2, kVar2.X);
                            break;
                        case 43:
                            mVar2.d = typedArrayObtainStyledAttributes.getFloat(index2, mVar2.d);
                            break;
                        case 44:
                            nVar2.m = true;
                            nVar2.n = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.n);
                            break;
                        case 45:
                            nVar2.c = typedArrayObtainStyledAttributes.getFloat(index2, nVar2.c);
                            break;
                        case 46:
                            nVar2.d = typedArrayObtainStyledAttributes.getFloat(index2, nVar2.d);
                            break;
                        case 47:
                            nVar2.e = typedArrayObtainStyledAttributes.getFloat(index2, nVar2.e);
                            break;
                        case 48:
                            nVar2.f = typedArrayObtainStyledAttributes.getFloat(index2, nVar2.f);
                            break;
                        case 49:
                            nVar2.g = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.g);
                            break;
                        case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                            nVar2.h = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.h);
                            break;
                        case 51:
                            nVar2.j = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.j);
                            break;
                        case 52:
                            nVar2.k = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.k);
                            break;
                        case 53:
                            nVar2.l = typedArrayObtainStyledAttributes.getDimension(index2, nVar2.l);
                            break;
                        case 54:
                            kVar2.Y = typedArrayObtainStyledAttributes.getInt(index2, kVar2.Y);
                            break;
                        case 55:
                            kVar2.Z = typedArrayObtainStyledAttributes.getInt(index2, kVar2.Z);
                            break;
                        case 56:
                            kVar2.a0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.a0);
                            break;
                        case 57:
                            kVar2.b0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.b0);
                            break;
                        case 58:
                            kVar2.c0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.c0);
                            break;
                        case 59:
                            kVar2.d0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.d0);
                            break;
                        case 60:
                            nVar2.b = typedArrayObtainStyledAttributes.getFloat(index2, nVar2.b);
                            break;
                        case 61:
                            kVar2.A = j(typedArrayObtainStyledAttributes, index2, kVar2.A);
                            break;
                        case 62:
                            kVar2.B = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.B);
                            break;
                        case 63:
                            kVar2.C = typedArrayObtainStyledAttributes.getFloat(index2, kVar2.C);
                            break;
                        case 64:
                            lVar2.b = j(typedArrayObtainStyledAttributes, index2, lVar2.b);
                            break;
                        case 65:
                            if (typedArrayObtainStyledAttributes.peekValue(index2).type == 3) {
                                lVar2.d = typedArrayObtainStyledAttributes.getString(index2);
                                break;
                            } else {
                                lVar2.d = androidx.constraintlayout.core.motion.utils.e.d[typedArrayObtainStyledAttributes.getInteger(index2, 0)];
                                break;
                            }
                        case 66:
                            lVar2.f = typedArrayObtainStyledAttributes.getInt(index2, 0);
                            break;
                        case 67:
                            lVar2.h = typedArrayObtainStyledAttributes.getFloat(index2, lVar2.h);
                            break;
                        case 68:
                            mVar2.e = typedArrayObtainStyledAttributes.getFloat(index2, mVar2.e);
                            break;
                        case 69:
                            kVar2.e0 = typedArrayObtainStyledAttributes.getFloat(index2, 1.0f);
                            break;
                        case 70:
                            kVar2.f0 = typedArrayObtainStyledAttributes.getFloat(index2, 1.0f);
                            break;
                        case 71:
                            Log.e("ConstraintSet", "CURRENTLY UNSUPPORTED");
                            break;
                        case 72:
                            kVar2.g0 = typedArrayObtainStyledAttributes.getInt(index2, kVar2.g0);
                            break;
                        case 73:
                            kVar2.h0 = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.h0);
                            break;
                        case 74:
                            kVar2.k0 = typedArrayObtainStyledAttributes.getString(index2);
                            break;
                        case 75:
                            kVar2.o0 = typedArrayObtainStyledAttributes.getBoolean(index2, kVar2.o0);
                            break;
                        case 76:
                            lVar2.e = typedArrayObtainStyledAttributes.getInt(index2, lVar2.e);
                            break;
                        case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                            kVar2.l0 = typedArrayObtainStyledAttributes.getString(index2);
                            break;
                        case 78:
                            mVar2.c = typedArrayObtainStyledAttributes.getInt(index2, mVar2.c);
                            break;
                        case 79:
                            lVar2.g = typedArrayObtainStyledAttributes.getFloat(index2, lVar2.g);
                            break;
                        case 80:
                            kVar2.m0 = typedArrayObtainStyledAttributes.getBoolean(index2, kVar2.m0);
                            break;
                        case 81:
                            kVar2.n0 = typedArrayObtainStyledAttributes.getBoolean(index2, kVar2.n0);
                            break;
                        case 82:
                            lVar2.c = typedArrayObtainStyledAttributes.getInteger(index2, lVar2.c);
                            break;
                        case 83:
                            nVar2.i = j(typedArrayObtainStyledAttributes, index2, nVar2.i);
                            break;
                        case 84:
                            lVar2.j = typedArrayObtainStyledAttributes.getInteger(index2, lVar2.j);
                            break;
                        case 85:
                            lVar2.i = typedArrayObtainStyledAttributes.getFloat(index2, lVar2.i);
                            break;
                        case 86:
                            int i6 = typedArrayObtainStyledAttributes.peekValue(index2).type;
                            if (i6 == 1) {
                                int resourceId5 = typedArrayObtainStyledAttributes.getResourceId(index2, -1);
                                lVar2.m = resourceId5;
                                if (resourceId5 != -1) {
                                    lVar2.l = -2;
                                    break;
                                } else {
                                    break;
                                }
                            } else if (i6 == 3) {
                                String string2 = typedArrayObtainStyledAttributes.getString(index2);
                                lVar2.k = string2;
                                if (string2.indexOf("/") > 0) {
                                    lVar2.m = typedArrayObtainStyledAttributes.getResourceId(index2, -1);
                                    lVar2.l = -2;
                                    break;
                                } else {
                                    lVar2.l = -1;
                                    break;
                                }
                            } else {
                                lVar2.l = typedArrayObtainStyledAttributes.getInteger(index2, lVar2.m);
                                break;
                            }
                        case 87:
                            Log.w("ConstraintSet", "unused attribute 0x" + Integer.toHexString(index2) + "   " + sparseIntArray2.get(index2));
                            break;
                        case 88:
                        case 89:
                        case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                        default:
                            Log.w("ConstraintSet", "Unknown attribute 0x" + Integer.toHexString(index2) + "   " + sparseIntArray2.get(index2));
                            break;
                        case 91:
                            kVar2.r = j(typedArrayObtainStyledAttributes, index2, kVar2.r);
                            break;
                        case 92:
                            kVar2.s = j(typedArrayObtainStyledAttributes, index2, kVar2.s);
                            break;
                        case 93:
                            kVar2.M = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.M);
                            break;
                        case 94:
                            kVar2.T = typedArrayObtainStyledAttributes.getDimensionPixelSize(index2, kVar2.T);
                            break;
                        case 95:
                            k(kVar2, typedArrayObtainStyledAttributes, index2, 0);
                            break;
                        case 96:
                            k(kVar2, typedArrayObtainStyledAttributes, index2, 1);
                            break;
                        case 97:
                            kVar2.p0 = typedArrayObtainStyledAttributes.getInt(index2, kVar2.p0);
                            break;
                    }
                    i4++;
                } else if (kVar2.k0 != null) {
                    kVar2.j0 = null;
                }
            }
        }
        typedArrayObtainStyledAttributes.recycle();
        return jVar;
    }

    public static int j(TypedArray typedArray, int i, int i2) {
        int resourceId = typedArray.getResourceId(i, i2);
        return resourceId == -1 ? typedArray.getInt(i, -1) : resourceId;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0044  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void k(java.lang.Object r7, android.content.res.TypedArray r8, int r9, int r10) {
        /*
            Method dump skipped, instructions count: 370
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.widget.o.k(java.lang.Object, android.content.res.TypedArray, int, int):void");
    }

    public static void l(e eVar, String str) {
        if (str != null) {
            int length = str.length();
            int iIndexOf = str.indexOf(44);
            char c = 65535;
            int i = 0;
            if (iIndexOf > 0 && iIndexOf < length - 1) {
                String strSubstring = str.substring(0, iIndexOf);
                if (strSubstring.equalsIgnoreCase("W")) {
                    c = 0;
                } else if (strSubstring.equalsIgnoreCase("H")) {
                    c = 1;
                }
                i = iIndexOf + 1;
            }
            int iIndexOf2 = str.indexOf(58);
            try {
                if (iIndexOf2 < 0 || iIndexOf2 >= length - 1) {
                    String strSubstring2 = str.substring(i);
                    if (strSubstring2.length() > 0) {
                        Float.parseFloat(strSubstring2);
                    }
                } else {
                    String strSubstring3 = str.substring(i, iIndexOf2);
                    String strSubstring4 = str.substring(iIndexOf2 + 1);
                    if (strSubstring3.length() > 0 && strSubstring4.length() > 0) {
                        float f2 = Float.parseFloat(strSubstring3);
                        float f3 = Float.parseFloat(strSubstring4);
                        if (f2 > DefinitionKt.NO_Float_VALUE && f3 > DefinitionKt.NO_Float_VALUE) {
                            if (c == 1) {
                                Math.abs(f3 / f2);
                            } else {
                                Math.abs(f2 / f3);
                            }
                        }
                    }
                }
            } catch (NumberFormatException unused) {
            }
        }
        eVar.G = str;
    }

    public static String m(int i) {
        switch (i) {
            case 1:
                return "left";
            case 2:
                return "right";
            case 3:
                return "top";
            case 4:
                return "bottom";
            case 5:
                return "baseline";
            case 6:
                return "start";
            case 7:
                return "end";
            default:
                return "undefined";
        }
    }

    public final void a(ConstraintLayout constraintLayout) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        b(constraintLayout);
        constraintLayout.setConstraintSet(null);
        constraintLayout.requestLayout();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public final void b(ConstraintLayout constraintLayout) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        HashSet hashSet;
        int i2;
        int i3;
        o oVar = this;
        int i4 = 1;
        int childCount = constraintLayout.getChildCount();
        HashMap map = oVar.d;
        HashSet hashSet2 = new HashSet(map.keySet());
        int i5 = 0;
        while (i5 < childCount) {
            View childAt = constraintLayout.getChildAt(i5);
            int id = childAt.getId();
            if (!map.containsKey(Integer.valueOf(id))) {
                Log.w("ConstraintSet", "id unknown " + AbstractC3134e6.h(childAt));
            } else {
                if (oVar.c && id == -1) {
                    throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
                }
                if (id != -1 && map.containsKey(Integer.valueOf(id))) {
                    hashSet2.remove(Integer.valueOf(id));
                    j jVar = (j) map.get(Integer.valueOf(id));
                    if (jVar != null) {
                        if (childAt instanceof a) {
                            k kVar = jVar.d;
                            kVar.i0 = i4;
                            a aVar = (a) childAt;
                            aVar.setId(id);
                            aVar.setType(kVar.g0);
                            aVar.setMargin(kVar.h0);
                            aVar.setAllowsGoneWidget(kVar.o0);
                            int[] iArr = kVar.j0;
                            if (iArr != null) {
                                aVar.setReferencedIds(iArr);
                            } else {
                                String str = kVar.k0;
                                if (str != null) {
                                    int[] iArrF = f(aVar, str);
                                    kVar.j0 = iArrF;
                                    aVar.setReferencedIds(iArrF);
                                }
                            }
                        }
                        e eVar = (e) childAt.getLayoutParams();
                        eVar.a();
                        jVar.a(eVar);
                        HashMap map2 = jVar.f;
                        i = i4;
                        Class<?> cls = childAt.getClass();
                        for (String str2 : map2.keySet()) {
                            b bVar = (b) map2.get(str2);
                            String strD = !bVar.a ? AbstractC0147y.d("set", str2) : str2;
                            HashSet hashSet3 = hashSet2;
                            try {
                                int iK = AbstractC0147y.k(bVar.c);
                                Class cls2 = Float.TYPE;
                                Class cls3 = Integer.TYPE;
                                switch (iK) {
                                    case 0:
                                        i3 = i5;
                                        cls.getMethod(strD, cls3).invoke(childAt, Integer.valueOf(bVar.d));
                                        break;
                                    case 1:
                                        i3 = i5;
                                        cls.getMethod(strD, cls2).invoke(childAt, Float.valueOf(bVar.e));
                                        break;
                                    case 2:
                                        i3 = i5;
                                        cls.getMethod(strD, cls3).invoke(childAt, Integer.valueOf(bVar.h));
                                        break;
                                    case 3:
                                        Method method = cls.getMethod(strD, Drawable.class);
                                        i3 = i5;
                                        try {
                                            ColorDrawable colorDrawable = new ColorDrawable();
                                            colorDrawable.setColor(bVar.h);
                                            method.invoke(childAt, colorDrawable);
                                        } catch (IllegalAccessException e2) {
                                            e = e2;
                                            StringBuilder sbY = android.support.v4.media.session.a.y(" Custom Attribute \"", str2, "\" not found on ");
                                            sbY.append(cls.getName());
                                            Log.e("TransitionLayout", sbY.toString(), e);
                                            hashSet2 = hashSet3;
                                            i5 = i3;
                                        } catch (NoSuchMethodException e3) {
                                            e = e3;
                                            Log.e("TransitionLayout", cls.getName() + " must have a method " + strD, e);
                                            hashSet2 = hashSet3;
                                            i5 = i3;
                                        } catch (InvocationTargetException e4) {
                                            e = e4;
                                            StringBuilder sbY2 = android.support.v4.media.session.a.y(" Custom Attribute \"", str2, "\" not found on ");
                                            sbY2.append(cls.getName());
                                            Log.e("TransitionLayout", sbY2.toString(), e);
                                            hashSet2 = hashSet3;
                                            i5 = i3;
                                        }
                                    case 4:
                                        cls.getMethod(strD, CharSequence.class).invoke(childAt, bVar.f);
                                        i3 = i5;
                                        break;
                                    case 5:
                                        cls.getMethod(strD, Boolean.TYPE).invoke(childAt, Boolean.valueOf(bVar.g));
                                        i3 = i5;
                                        break;
                                    case 6:
                                        cls.getMethod(strD, cls2).invoke(childAt, Float.valueOf(bVar.e));
                                        i3 = i5;
                                        break;
                                    case 7:
                                        cls.getMethod(strD, cls3).invoke(childAt, Integer.valueOf(bVar.d));
                                        i3 = i5;
                                        break;
                                    default:
                                        i3 = i5;
                                        break;
                                }
                            } catch (IllegalAccessException e5) {
                                e = e5;
                                i3 = i5;
                            } catch (NoSuchMethodException e6) {
                                e = e6;
                                i3 = i5;
                            } catch (InvocationTargetException e7) {
                                e = e7;
                                i3 = i5;
                            }
                            hashSet2 = hashSet3;
                            i5 = i3;
                        }
                        hashSet = hashSet2;
                        i2 = i5;
                        childAt.setLayoutParams(eVar);
                        m mVar = jVar.b;
                        if (mVar.c == 0) {
                            childAt.setVisibility(mVar.b);
                        }
                        childAt.setAlpha(mVar.d);
                        n nVar = jVar.e;
                        childAt.setRotation(nVar.b);
                        childAt.setRotationX(nVar.c);
                        childAt.setRotationY(nVar.d);
                        childAt.setScaleX(nVar.e);
                        childAt.setScaleY(nVar.f);
                        if (nVar.i != -1) {
                            if (((View) childAt.getParent()).findViewById(nVar.i) != null) {
                                float bottom = (r1.getBottom() + r1.getTop()) / 2.0f;
                                float right = (r1.getRight() + r1.getLeft()) / 2.0f;
                                if (childAt.getRight() - childAt.getLeft() > 0 && childAt.getBottom() - childAt.getTop() > 0) {
                                    childAt.setPivotX(right - childAt.getLeft());
                                    childAt.setPivotY(bottom - childAt.getTop());
                                }
                            }
                        } else {
                            if (!Float.isNaN(nVar.g)) {
                                childAt.setPivotX(nVar.g);
                            }
                            if (!Float.isNaN(nVar.h)) {
                                childAt.setPivotY(nVar.h);
                            }
                        }
                        childAt.setTranslationX(nVar.j);
                        childAt.setTranslationY(nVar.k);
                        childAt.setTranslationZ(nVar.l);
                        if (nVar.m) {
                            childAt.setElevation(nVar.n);
                        }
                    }
                }
                i5 = i2 + 1;
                oVar = this;
                i4 = i;
                hashSet2 = hashSet;
            }
            i = i4;
            hashSet = hashSet2;
            i2 = i5;
            i5 = i2 + 1;
            oVar = this;
            i4 = i;
            hashSet2 = hashSet;
        }
        int i6 = i4;
        Iterator it2 = hashSet2.iterator();
        while (it2.hasNext()) {
            Integer num = (Integer) it2.next();
            j jVar2 = (j) map.get(num);
            if (jVar2 != null) {
                k kVar2 = jVar2.d;
                if (kVar2.i0 == i6) {
                    a aVar2 = new a(constraintLayout.getContext());
                    aVar2.setId(num.intValue());
                    int[] iArr2 = kVar2.j0;
                    if (iArr2 != null) {
                        aVar2.setReferencedIds(iArr2);
                    } else {
                        String str3 = kVar2.k0;
                        if (str3 != null) {
                            int[] iArrF2 = f(aVar2, str3);
                            kVar2.j0 = iArrF2;
                            aVar2.setReferencedIds(iArrF2);
                        }
                    }
                    aVar2.setType(kVar2.g0);
                    aVar2.setMargin(kVar2.h0);
                    v vVar = ConstraintLayout.p;
                    e eVar2 = new e();
                    aVar2.k();
                    jVar2.a(eVar2);
                    constraintLayout.addView(aVar2, eVar2);
                }
                if (kVar2.a) {
                    View guideline = new Guideline(constraintLayout.getContext());
                    guideline.setId(num.intValue());
                    v vVar2 = ConstraintLayout.p;
                    e eVar3 = new e();
                    jVar2.a(eVar3);
                    constraintLayout.addView(guideline, eVar3);
                }
                i6 = 1;
            }
        }
        for (int i7 = 0; i7 < childCount; i7++) {
            View childAt2 = constraintLayout.getChildAt(i7);
            if (childAt2 instanceof c) {
                ((c) childAt2).f(constraintLayout);
            }
        }
    }

    public final void c(int i) {
        j jVar;
        HashMap map = this.d;
        if (!map.containsKey(Integer.valueOf(i)) || (jVar = (j) map.get(Integer.valueOf(i))) == null) {
            return;
        }
        k kVar = jVar.d;
        kVar.o = -1;
        kVar.p = -1;
        kVar.J = 0;
        kVar.Q = Integer.MIN_VALUE;
    }

    public final void d(ConstraintLayout constraintLayout) {
        int i;
        HashMap map;
        HashMap map2;
        o oVar = this;
        int childCount = constraintLayout.getChildCount();
        HashMap map3 = oVar.d;
        map3.clear();
        int i2 = 0;
        while (i2 < childCount) {
            View childAt = constraintLayout.getChildAt(i2);
            e eVar = (e) childAt.getLayoutParams();
            int id = childAt.getId();
            if (oVar.c && id == -1) {
                throw new RuntimeException("All children of ConstraintLayout must have ids to use ConstraintSet");
            }
            if (!map3.containsKey(Integer.valueOf(id))) {
                map3.put(Integer.valueOf(id), new j());
            }
            j jVar = (j) map3.get(Integer.valueOf(id));
            if (jVar == null) {
                i = childCount;
                map = map3;
            } else {
                HashMap map4 = oVar.b;
                HashMap map5 = new HashMap();
                Class<?> cls = childAt.getClass();
                for (String str : map4.keySet()) {
                    b bVar = (b) map4.get(str);
                    int i3 = childCount;
                    try {
                        if (str.equals("BackgroundColor")) {
                            map2 = map3;
                            try {
                                map5.put(str, new b(bVar, Integer.valueOf(((ColorDrawable) childAt.getBackground()).getColor())));
                            } catch (IllegalAccessException e2) {
                                e = e2;
                                StringBuilder sbY = android.support.v4.media.session.a.y(" Custom Attribute \"", str, "\" not found on ");
                                sbY.append(cls.getName());
                                Log.e("TransitionLayout", sbY.toString(), e);
                                childCount = i3;
                                map3 = map2;
                            } catch (NoSuchMethodException e3) {
                                e = e3;
                                Log.e("TransitionLayout", cls.getName() + " must have a method " + str, e);
                                childCount = i3;
                                map3 = map2;
                            } catch (InvocationTargetException e4) {
                                e = e4;
                                StringBuilder sbY2 = android.support.v4.media.session.a.y(" Custom Attribute \"", str, "\" not found on ");
                                sbY2.append(cls.getName());
                                Log.e("TransitionLayout", sbY2.toString(), e);
                                childCount = i3;
                                map3 = map2;
                            }
                        } else {
                            map2 = map3;
                            map5.put(str, new b(bVar, cls.getMethod("getMap" + str, null).invoke(childAt, null)));
                        }
                    } catch (IllegalAccessException e5) {
                        e = e5;
                        map2 = map3;
                    } catch (NoSuchMethodException e6) {
                        e = e6;
                        map2 = map3;
                    } catch (InvocationTargetException e7) {
                        e = e7;
                        map2 = map3;
                    }
                    childCount = i3;
                    map3 = map2;
                }
                i = childCount;
                map = map3;
                jVar.f = map5;
                jVar.b(id, eVar);
                int visibility = childAt.getVisibility();
                m mVar = jVar.b;
                mVar.b = visibility;
                mVar.d = childAt.getAlpha();
                float rotation = childAt.getRotation();
                n nVar = jVar.e;
                nVar.b = rotation;
                nVar.c = childAt.getRotationX();
                nVar.d = childAt.getRotationY();
                nVar.e = childAt.getScaleX();
                nVar.f = childAt.getScaleY();
                float pivotX = childAt.getPivotX();
                float pivotY = childAt.getPivotY();
                if (pivotX != 0.0d || pivotY != 0.0d) {
                    nVar.g = pivotX;
                    nVar.h = pivotY;
                }
                nVar.j = childAt.getTranslationX();
                nVar.k = childAt.getTranslationY();
                nVar.l = childAt.getTranslationZ();
                if (nVar.m) {
                    nVar.n = childAt.getElevation();
                }
                if (childAt instanceof a) {
                    a aVar = (a) childAt;
                    boolean allowsGoneWidget = aVar.getAllowsGoneWidget();
                    k kVar = jVar.d;
                    kVar.o0 = allowsGoneWidget;
                    kVar.j0 = aVar.getReferencedIds();
                    kVar.g0 = aVar.getType();
                    kVar.h0 = aVar.getMargin();
                }
            }
            i2++;
            oVar = this;
            childCount = i;
            map3 = map;
        }
    }

    public final void e(int i, int i2, int i3, int i4, int i5) {
        HashMap map = this.d;
        if (!map.containsKey(Integer.valueOf(i))) {
            map.put(Integer.valueOf(i), new j());
        }
        j jVar = (j) map.get(Integer.valueOf(i));
        if (jVar == null) {
            return;
        }
        k kVar = jVar.d;
        switch (i2) {
            case 1:
                if (i4 == 1) {
                    kVar.i = i3;
                    kVar.j = -1;
                } else {
                    if (i4 != 2) {
                        throw new IllegalArgumentException("Left to " + m(i4) + " undefined");
                    }
                    kVar.j = i3;
                    kVar.i = -1;
                }
                kVar.G = i5;
                return;
            case 2:
                if (i4 == 1) {
                    kVar.k = i3;
                    kVar.l = -1;
                } else {
                    if (i4 != 2) {
                        throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                    }
                    kVar.l = i3;
                    kVar.k = -1;
                }
                kVar.H = i5;
                return;
            case 3:
                if (i4 == 3) {
                    kVar.m = i3;
                    kVar.n = -1;
                    kVar.q = -1;
                    kVar.r = -1;
                    kVar.s = -1;
                } else {
                    if (i4 != 4) {
                        throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                    }
                    kVar.n = i3;
                    kVar.m = -1;
                    kVar.q = -1;
                    kVar.r = -1;
                    kVar.s = -1;
                }
                kVar.I = i5;
                return;
            case 4:
                if (i4 == 4) {
                    kVar.p = i3;
                    kVar.o = -1;
                    kVar.q = -1;
                    kVar.r = -1;
                    kVar.s = -1;
                } else {
                    if (i4 != 3) {
                        throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                    }
                    kVar.o = i3;
                    kVar.p = -1;
                    kVar.q = -1;
                    kVar.r = -1;
                    kVar.s = -1;
                }
                kVar.J = i5;
                return;
            case 5:
                if (i4 == 5) {
                    kVar.q = i3;
                    kVar.p = -1;
                    kVar.o = -1;
                    kVar.m = -1;
                    kVar.n = -1;
                    return;
                }
                if (i4 == 3) {
                    kVar.r = i3;
                    kVar.p = -1;
                    kVar.o = -1;
                    kVar.m = -1;
                    kVar.n = -1;
                    return;
                }
                if (i4 != 4) {
                    throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                }
                kVar.s = i3;
                kVar.p = -1;
                kVar.o = -1;
                kVar.m = -1;
                kVar.n = -1;
                return;
            case 6:
                if (i4 == 6) {
                    kVar.u = i3;
                    kVar.t = -1;
                } else {
                    if (i4 != 7) {
                        throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                    }
                    kVar.t = i3;
                    kVar.u = -1;
                }
                kVar.L = i5;
                return;
            case 7:
                if (i4 == 7) {
                    kVar.w = i3;
                    kVar.v = -1;
                } else {
                    if (i4 != 6) {
                        throw new IllegalArgumentException("right to " + m(i4) + " undefined");
                    }
                    kVar.v = i3;
                    kVar.w = -1;
                }
                kVar.K = i5;
                return;
            default:
                throw new IllegalArgumentException(m(i2) + " to " + m(i4) + " unknown");
        }
    }

    public final j h(int i) {
        HashMap map = this.d;
        if (!map.containsKey(Integer.valueOf(i))) {
            map.put(Integer.valueOf(i), new j());
        }
        return (j) map.get(Integer.valueOf(i));
    }

    public final void i(Context context, int i) throws XmlPullParserException, Resources.NotFoundException, IOException {
        XmlResourceParser xml = context.getResources().getXml(i);
        try {
            for (int eventType = xml.getEventType(); eventType != 1; eventType = xml.next()) {
                if (eventType == 2) {
                    String name = xml.getName();
                    j jVarG = g(context, Xml.asAttributeSet(xml), false);
                    if (name.equalsIgnoreCase("Guideline")) {
                        jVarG.d.a = true;
                    }
                    this.d.put(Integer.valueOf(jVarG.a), jVarG);
                }
            }
        } catch (IOException e2) {
            Log.e("ConstraintSet", "Error parsing resource: " + i, e2);
        } catch (XmlPullParserException e3) {
            Log.e("ConstraintSet", "Error parsing resource: " + i, e3);
        }
    }
}
