package androidx.camera.camera2.internal;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.CamcorderProfile;
import android.media.MediaRecorder;
import android.os.Build;
import android.util.Pair;
import android.util.Range;
import android.util.Size;
import androidx.camera.camera2.internal.compat.CameraAccessExceptionCompat;
import androidx.camera.camera2.internal.compat.quirk.ExtraSupportedSurfaceCombinationsQuirk;
import androidx.camera.core.CameraUnavailableException;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0158a;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0169h;
import androidx.camera.core.impl.C0170i;
import androidx.camera.core.impl.u0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.onetrust.otpublishers.headless.Public.OTVendorListMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/* loaded from: classes.dex */
public final class f0 {
    public final String i;
    public final InterfaceC0127d j;
    public final androidx.camera.camera2.internal.compat.k k;
    public final androidx.webkit.internal.p l;
    public final int m;
    public final boolean n;
    public final boolean o;
    public final boolean p;
    public final boolean q;
    public final boolean r;
    public C0170i s;
    public final W u;
    public final C3083y1 x;
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public final ArrayList c = new ArrayList();
    public final ArrayList d = new ArrayList();
    public final HashMap e = new HashMap();
    public final ArrayList f = new ArrayList();
    public final ArrayList g = new ArrayList();
    public final ArrayList h = new ArrayList();
    public final ArrayList t = new ArrayList();
    public final com.google.mlkit.common.sdkinternal.b v = new com.google.mlkit.common.sdkinternal.b(1);
    public final com.google.android.gms.auth.api.signin.internal.h w = new com.google.android.gms.auth.api.signin.internal.h(5);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v21, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v23, types: [java.util.List] */
    public f0(Context context, String str, androidx.camera.camera2.internal.compat.q qVar, InterfaceC0127d interfaceC0127d) throws CameraUnavailableException, NumberFormatException {
        ArrayList arrayListSingletonList;
        int[] outputFormats;
        long[] jArr;
        u0 u0Var;
        int i;
        int[] iArr;
        boolean z;
        this.n = false;
        this.o = false;
        this.p = false;
        this.q = false;
        this.r = false;
        str.getClass();
        this.i = str;
        interfaceC0127d.getClass();
        this.j = interfaceC0127d;
        this.l = new androidx.webkit.internal.p(2);
        this.u = W.b(context);
        try {
            androidx.camera.camera2.internal.compat.k kVarB = qVar.b(str);
            this.k = kVarB;
            Integer num = (Integer) kVarB.a(CameraCharacteristics.INFO_SUPPORTED_HARDWARE_LEVEL);
            this.m = num != null ? num.intValue() : 2;
            int[] iArr2 = (int[]) kVarB.a(CameraCharacteristics.REQUEST_AVAILABLE_CAPABILITIES);
            if (iArr2 != null) {
                for (int i2 : iArr2) {
                    if (i2 == 3) {
                        this.n = true;
                    } else if (i2 == 6) {
                        this.o = true;
                    } else if (Build.VERSION.SDK_INT >= 31 && i2 == 16) {
                        this.r = true;
                    }
                }
            }
            this.x = new C3083y1(this.k);
            ArrayList arrayList = new ArrayList();
            ArrayList arrayList2 = new ArrayList();
            androidx.camera.core.impl.t0 t0Var = new androidx.camera.core.impl.t0();
            u0 u0Var2 = u0.MAXIMUM;
            AbstractC0147y.i(1, u0Var2, 0L, t0Var);
            androidx.camera.core.impl.t0 t0VarB = AbstractC0147y.b(arrayList2, t0Var);
            AbstractC0147y.i(3, u0Var2, 0L, t0VarB);
            androidx.camera.core.impl.t0 t0VarB2 = AbstractC0147y.b(arrayList2, t0VarB);
            AbstractC0147y.i(2, u0Var2, 0L, t0VarB2);
            androidx.camera.core.impl.t0 t0VarB3 = AbstractC0147y.b(arrayList2, t0VarB2);
            u0 u0Var3 = u0.PREVIEW;
            t0VarB3.a(new C0169h(1, u0Var3, 0L));
            AbstractC0147y.i(3, u0Var2, 0L, t0VarB3);
            androidx.camera.core.impl.t0 t0VarB4 = AbstractC0147y.b(arrayList2, t0VarB3);
            t0VarB4.a(new C0169h(2, u0Var3, 0L));
            AbstractC0147y.i(3, u0Var2, 0L, t0VarB4);
            androidx.camera.core.impl.t0 t0VarB5 = AbstractC0147y.b(arrayList2, t0VarB4);
            t0VarB5.a(new C0169h(1, u0Var3, 0L));
            AbstractC0147y.i(1, u0Var3, 0L, t0VarB5);
            androidx.camera.core.impl.t0 t0VarB6 = AbstractC0147y.b(arrayList2, t0VarB5);
            t0VarB6.a(new C0169h(1, u0Var3, 0L));
            AbstractC0147y.i(2, u0Var3, 0L, t0VarB6);
            androidx.camera.core.impl.t0 t0VarB7 = AbstractC0147y.b(arrayList2, t0VarB6);
            t0VarB7.a(new C0169h(1, u0Var3, 0L));
            t0VarB7.a(new C0169h(2, u0Var3, 0L));
            AbstractC0147y.i(3, u0Var2, 0L, t0VarB7);
            arrayList2.add(t0VarB7);
            arrayList.addAll(arrayList2);
            int i3 = this.m;
            u0 u0Var4 = u0.RECORD;
            if (i3 == 0 || i3 == 1 || i3 == 3) {
                ArrayList arrayList3 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var2 = new androidx.camera.core.impl.t0();
                t0Var2.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var4, 0L, t0Var2);
                androidx.camera.core.impl.t0 t0VarB8 = AbstractC0147y.b(arrayList3, t0Var2);
                t0VarB8.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var4, 0L, t0VarB8);
                androidx.camera.core.impl.t0 t0VarB9 = AbstractC0147y.b(arrayList3, t0VarB8);
                t0VarB9.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var4, 0L, t0VarB9);
                androidx.camera.core.impl.t0 t0VarB10 = AbstractC0147y.b(arrayList3, t0VarB9);
                t0VarB10.a(new C0169h(1, u0Var3, 0L));
                t0VarB10.a(new C0169h(1, u0Var4, 0L));
                AbstractC0147y.i(3, u0Var4, 0L, t0VarB10);
                androidx.camera.core.impl.t0 t0VarB11 = AbstractC0147y.b(arrayList3, t0VarB10);
                t0VarB11.a(new C0169h(1, u0Var3, 0L));
                t0VarB11.a(new C0169h(2, u0Var4, 0L));
                AbstractC0147y.i(3, u0Var4, 0L, t0VarB11);
                androidx.camera.core.impl.t0 t0VarB12 = AbstractC0147y.b(arrayList3, t0VarB11);
                t0VarB12.a(new C0169h(2, u0Var3, 0L));
                t0VarB12.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB12);
                arrayList3.add(t0VarB12);
                arrayList.addAll(arrayList3);
            }
            u0 u0Var5 = u0.VGA;
            if (i3 == 1 || i3 == 3) {
                ArrayList arrayList4 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var3 = new androidx.camera.core.impl.t0();
                t0Var3.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var2, 0L, t0Var3);
                androidx.camera.core.impl.t0 t0VarB13 = AbstractC0147y.b(arrayList4, t0Var3);
                t0VarB13.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB13);
                androidx.camera.core.impl.t0 t0VarB14 = AbstractC0147y.b(arrayList4, t0VarB13);
                t0VarB14.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB14);
                androidx.camera.core.impl.t0 t0VarB15 = AbstractC0147y.b(arrayList4, t0VarB14);
                t0VarB15.a(new C0169h(1, u0Var3, 0L));
                t0VarB15.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB15);
                androidx.camera.core.impl.t0 t0VarB16 = AbstractC0147y.b(arrayList4, t0VarB15);
                t0VarB16.a(new C0169h(2, u0Var5, 0L));
                t0VarB16.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB16);
                androidx.camera.core.impl.t0 t0VarB17 = AbstractC0147y.b(arrayList4, t0VarB16);
                t0VarB17.a(new C0169h(2, u0Var5, 0L));
                t0VarB17.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB17);
                arrayList4.add(t0VarB17);
                arrayList.addAll(arrayList4);
            }
            if (this.n) {
                ArrayList arrayList5 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var4 = new androidx.camera.core.impl.t0();
                AbstractC0147y.i(5, u0Var2, 0L, t0Var4);
                androidx.camera.core.impl.t0 t0VarB18 = AbstractC0147y.b(arrayList5, t0Var4);
                t0VarB18.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB18);
                androidx.camera.core.impl.t0 t0VarB19 = AbstractC0147y.b(arrayList5, t0VarB18);
                t0VarB19.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB19);
                androidx.camera.core.impl.t0 t0VarB20 = AbstractC0147y.b(arrayList5, t0VarB19);
                t0VarB20.a(new C0169h(1, u0Var3, 0L));
                t0VarB20.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB20);
                androidx.camera.core.impl.t0 t0VarB21 = AbstractC0147y.b(arrayList5, t0VarB20);
                t0VarB21.a(new C0169h(1, u0Var3, 0L));
                t0VarB21.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB21);
                androidx.camera.core.impl.t0 t0VarB22 = AbstractC0147y.b(arrayList5, t0VarB21);
                t0VarB22.a(new C0169h(2, u0Var3, 0L));
                t0VarB22.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB22);
                androidx.camera.core.impl.t0 t0VarB23 = AbstractC0147y.b(arrayList5, t0VarB22);
                t0VarB23.a(new C0169h(1, u0Var3, 0L));
                t0VarB23.a(new C0169h(3, u0Var2, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB23);
                androidx.camera.core.impl.t0 t0VarB24 = AbstractC0147y.b(arrayList5, t0VarB23);
                t0VarB24.a(new C0169h(2, u0Var3, 0L));
                t0VarB24.a(new C0169h(3, u0Var2, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB24);
                arrayList5.add(t0VarB24);
                arrayList.addAll(arrayList5);
            }
            if (this.o && i3 == 0) {
                ArrayList arrayList6 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var5 = new androidx.camera.core.impl.t0();
                t0Var5.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var2, 0L, t0Var5);
                androidx.camera.core.impl.t0 t0VarB25 = AbstractC0147y.b(arrayList6, t0Var5);
                t0VarB25.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB25);
                androidx.camera.core.impl.t0 t0VarB26 = AbstractC0147y.b(arrayList6, t0VarB25);
                t0VarB26.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB26);
                arrayList6.add(t0VarB26);
                arrayList.addAll(arrayList6);
            }
            if (i3 == 3) {
                ArrayList arrayList7 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var6 = new androidx.camera.core.impl.t0();
                t0Var6.a(new C0169h(1, u0Var3, 0L));
                t0Var6.a(new C0169h(1, u0Var5, 0L));
                t0Var6.a(new C0169h(2, u0Var2, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0Var6);
                androidx.camera.core.impl.t0 t0VarB27 = AbstractC0147y.b(arrayList7, t0Var6);
                t0VarB27.a(new C0169h(1, u0Var3, 0L));
                t0VarB27.a(new C0169h(1, u0Var5, 0L));
                t0VarB27.a(new C0169h(3, u0Var2, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB27);
                arrayList7.add(t0VarB27);
                arrayList.addAll(arrayList7);
            }
            ArrayList arrayList8 = this.a;
            arrayList8.addAll(arrayList);
            if (((ExtraSupportedSurfaceCombinationsQuirk) this.l.b) == null) {
                arrayListSingletonList = new ArrayList();
            } else {
                androidx.camera.core.impl.t0 t0Var7 = ExtraSupportedSurfaceCombinationsQuirk.a;
                String str2 = Build.DEVICE;
                if ("heroqltevzw".equalsIgnoreCase(str2) || "heroqltetmo".equalsIgnoreCase(str2)) {
                    ArrayList arrayList9 = new ArrayList();
                    arrayListSingletonList = arrayList9;
                    if (this.i.equals("1")) {
                        arrayList9.add(ExtraSupportedSurfaceCombinationsQuirk.a);
                        arrayListSingletonList = arrayList9;
                    }
                } else {
                    arrayListSingletonList = ((!OTVendorListMode.GOOGLE.equalsIgnoreCase(Build.BRAND) ? false : ExtraSupportedSurfaceCombinationsQuirk.c.contains(Build.MODEL.toUpperCase(Locale.US))) || ExtraSupportedSurfaceCombinationsQuirk.b()) ? Collections.singletonList(ExtraSupportedSurfaceCombinationsQuirk.b) : Collections.EMPTY_LIST;
                }
            }
            arrayList8.addAll(arrayListSingletonList);
            if (this.r) {
                ArrayList arrayList10 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var8 = new androidx.camera.core.impl.t0();
                u0 u0Var6 = u0.ULTRA_MAXIMUM;
                t0Var8.a(new C0169h(2, u0Var6, 0L));
                t0Var8.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var4, 0L, t0Var8);
                androidx.camera.core.impl.t0 t0VarB28 = AbstractC0147y.b(arrayList10, t0Var8);
                t0VarB28.a(new C0169h(3, u0Var6, 0L));
                t0VarB28.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var4, 0L, t0VarB28);
                androidx.camera.core.impl.t0 t0VarB29 = AbstractC0147y.b(arrayList10, t0VarB28);
                t0VarB29.a(new C0169h(5, u0Var6, 0L));
                t0VarB29.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var4, 0L, t0VarB29);
                androidx.camera.core.impl.t0 t0VarB30 = AbstractC0147y.b(arrayList10, t0VarB29);
                t0VarB30.a(new C0169h(2, u0Var6, 0L));
                t0VarB30.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB30);
                androidx.camera.core.impl.t0 t0VarB31 = AbstractC0147y.b(arrayList10, t0VarB30);
                t0VarB31.a(new C0169h(3, u0Var6, 0L));
                t0VarB31.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB31);
                androidx.camera.core.impl.t0 t0VarB32 = AbstractC0147y.b(arrayList10, t0VarB31);
                t0VarB32.a(new C0169h(5, u0Var6, 0L));
                t0VarB32.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB32);
                androidx.camera.core.impl.t0 t0VarB33 = AbstractC0147y.b(arrayList10, t0VarB32);
                t0VarB33.a(new C0169h(2, u0Var6, 0L));
                t0VarB33.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB33);
                androidx.camera.core.impl.t0 t0VarB34 = AbstractC0147y.b(arrayList10, t0VarB33);
                t0VarB34.a(new C0169h(3, u0Var6, 0L));
                t0VarB34.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB34);
                androidx.camera.core.impl.t0 t0VarB35 = AbstractC0147y.b(arrayList10, t0VarB34);
                t0VarB35.a(new C0169h(5, u0Var6, 0L));
                t0VarB35.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB35);
                androidx.camera.core.impl.t0 t0VarB36 = AbstractC0147y.b(arrayList10, t0VarB35);
                t0VarB36.a(new C0169h(2, u0Var6, 0L));
                t0VarB36.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB36);
                androidx.camera.core.impl.t0 t0VarB37 = AbstractC0147y.b(arrayList10, t0VarB36);
                t0VarB37.a(new C0169h(3, u0Var6, 0L));
                t0VarB37.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB37);
                androidx.camera.core.impl.t0 t0VarB38 = AbstractC0147y.b(arrayList10, t0VarB37);
                t0VarB38.a(new C0169h(5, u0Var6, 0L));
                t0VarB38.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(5, u0Var2, 0L, t0VarB38);
                arrayList10.add(t0VarB38);
                this.b.addAll(arrayList10);
            }
            boolean zHasSystemFeature = context.getPackageManager().hasSystemFeature("android.hardware.camera.concurrent");
            this.p = zHasSystemFeature;
            u0 u0Var7 = u0.s1440p;
            if (zHasSystemFeature) {
                ArrayList arrayList11 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var9 = new androidx.camera.core.impl.t0();
                AbstractC0147y.i(2, u0Var7, 0L, t0Var9);
                androidx.camera.core.impl.t0 t0VarB39 = AbstractC0147y.b(arrayList11, t0Var9);
                AbstractC0147y.i(1, u0Var7, 0L, t0VarB39);
                androidx.camera.core.impl.t0 t0VarB40 = AbstractC0147y.b(arrayList11, t0VarB39);
                AbstractC0147y.i(3, u0Var7, 0L, t0VarB40);
                androidx.camera.core.impl.t0 t0VarB41 = AbstractC0147y.b(arrayList11, t0VarB40);
                u0 u0Var8 = u0.s720p;
                t0VarB41.a(new C0169h(2, u0Var8, 0L));
                AbstractC0147y.i(3, u0Var7, 0L, t0VarB41);
                androidx.camera.core.impl.t0 t0VarB42 = AbstractC0147y.b(arrayList11, t0VarB41);
                t0VarB42.a(new C0169h(1, u0Var8, 0L));
                AbstractC0147y.i(3, u0Var7, 0L, t0VarB42);
                androidx.camera.core.impl.t0 t0VarB43 = AbstractC0147y.b(arrayList11, t0VarB42);
                t0VarB43.a(new C0169h(2, u0Var8, 0L));
                AbstractC0147y.i(2, u0Var7, 0L, t0VarB43);
                androidx.camera.core.impl.t0 t0VarB44 = AbstractC0147y.b(arrayList11, t0VarB43);
                t0VarB44.a(new C0169h(2, u0Var8, 0L));
                AbstractC0147y.i(1, u0Var7, 0L, t0VarB44);
                androidx.camera.core.impl.t0 t0VarB45 = AbstractC0147y.b(arrayList11, t0VarB44);
                t0VarB45.a(new C0169h(1, u0Var8, 0L));
                AbstractC0147y.i(2, u0Var7, 0L, t0VarB45);
                androidx.camera.core.impl.t0 t0VarB46 = AbstractC0147y.b(arrayList11, t0VarB45);
                t0VarB46.a(new C0169h(1, u0Var8, 0L));
                AbstractC0147y.i(1, u0Var7, 0L, t0VarB46);
                arrayList11.add(t0VarB46);
                this.c.addAll(arrayList11);
            }
            if (this.x.b) {
                ArrayList arrayList12 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var10 = new androidx.camera.core.impl.t0();
                AbstractC0147y.i(1, u0Var2, 0L, t0Var10);
                androidx.camera.core.impl.t0 t0VarB47 = AbstractC0147y.b(arrayList12, t0Var10);
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB47);
                androidx.camera.core.impl.t0 t0VarB48 = AbstractC0147y.b(arrayList12, t0VarB47);
                t0VarB48.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB48);
                androidx.camera.core.impl.t0 t0VarB49 = AbstractC0147y.b(arrayList12, t0VarB48);
                t0VarB49.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB49);
                androidx.camera.core.impl.t0 t0VarB50 = AbstractC0147y.b(arrayList12, t0VarB49);
                t0VarB50.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB50);
                androidx.camera.core.impl.t0 t0VarB51 = AbstractC0147y.b(arrayList12, t0VarB50);
                t0VarB51.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var4, 0L, t0VarB51);
                androidx.camera.core.impl.t0 t0VarB52 = AbstractC0147y.b(arrayList12, t0VarB51);
                t0VarB52.a(new C0169h(1, u0Var3, 0L));
                t0VarB52.a(new C0169h(1, u0Var4, 0L));
                AbstractC0147y.i(2, u0Var4, 0L, t0VarB52);
                androidx.camera.core.impl.t0 t0VarB53 = AbstractC0147y.b(arrayList12, t0VarB52);
                t0VarB53.a(new C0169h(1, u0Var3, 0L));
                t0VarB53.a(new C0169h(1, u0Var4, 0L));
                AbstractC0147y.i(3, u0Var4, 0L, t0VarB53);
                arrayList12.add(t0VarB53);
                this.f.addAll(arrayList12);
            }
            com.google.android.gms.internal.instantapps.a aVar = (com.google.android.gms.internal.instantapps.a) this.k.b().b;
            aVar.getClass();
            try {
                outputFormats = ((StreamConfigurationMap) aVar.b).getOutputFormats();
            } catch (IllegalArgumentException | NullPointerException e) {
                AbstractC3053s1.i("StreamConfigurationMapCompatBaseImpl", "Failed to get output formats from StreamConfigurationMap", e);
                outputFormats = null;
            }
            int[] iArr3 = outputFormats != null ? (int[]) outputFormats.clone() : null;
            if (iArr3 != null) {
                int length = iArr3.length;
                int i4 = 0;
                while (true) {
                    if (i4 >= length) {
                        break;
                    }
                    if (iArr3[i4] == 4101) {
                        ArrayList arrayList13 = new ArrayList();
                        androidx.camera.core.impl.t0 t0Var11 = new androidx.camera.core.impl.t0();
                        AbstractC0147y.i(4, u0Var2, 0L, t0Var11);
                        androidx.camera.core.impl.t0 t0VarB54 = AbstractC0147y.b(arrayList13, t0Var11);
                        t0VarB54.a(new C0169h(1, u0Var3, 0L));
                        AbstractC0147y.i(4, u0Var2, 0L, t0VarB54);
                        arrayList13.add(t0VarB54);
                        this.g.addAll(arrayList13);
                        break;
                    }
                    i4++;
                }
            }
            androidx.camera.camera2.internal.compat.k kVar = this.k;
            C0162c c0162c = e0.a;
            int i5 = Build.VERSION.SDK_INT;
            boolean z2 = (i5 < 33 || (jArr = (long[]) kVar.a(CameraCharacteristics.SCALER_AVAILABLE_STREAM_USE_CASES)) == null || jArr.length == 0) ? false : true;
            this.q = z2;
            if (!z2 || i5 < 33) {
                u0Var = u0Var7;
                i = i5;
            } else {
                ArrayList arrayList14 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var12 = new androidx.camera.core.impl.t0();
                AbstractC0147y.i(1, u0Var7, 4L, t0Var12);
                androidx.camera.core.impl.t0 t0VarB55 = AbstractC0147y.b(arrayList14, t0Var12);
                AbstractC0147y.i(2, u0Var7, 4L, t0VarB55);
                androidx.camera.core.impl.t0 t0VarB56 = AbstractC0147y.b(arrayList14, t0VarB55);
                AbstractC0147y.i(1, u0Var4, 3L, t0VarB56);
                androidx.camera.core.impl.t0 t0VarB57 = AbstractC0147y.b(arrayList14, t0VarB56);
                AbstractC0147y.i(2, u0Var4, 3L, t0VarB57);
                androidx.camera.core.impl.t0 t0VarB58 = AbstractC0147y.b(arrayList14, t0VarB57);
                AbstractC0147y.i(3, u0Var2, 2L, t0VarB58);
                androidx.camera.core.impl.t0 t0VarB59 = AbstractC0147y.b(arrayList14, t0VarB58);
                AbstractC0147y.i(2, u0Var2, 2L, t0VarB59);
                androidx.camera.core.impl.t0 t0VarB60 = AbstractC0147y.b(arrayList14, t0VarB59);
                t0VarB60.a(new C0169h(1, u0Var3, 1L));
                AbstractC0147y.i(3, u0Var2, 2L, t0VarB60);
                androidx.camera.core.impl.t0 t0VarB61 = AbstractC0147y.b(arrayList14, t0VarB60);
                t0VarB61.a(new C0169h(1, u0Var3, 1L));
                AbstractC0147y.i(2, u0Var2, 2L, t0VarB61);
                androidx.camera.core.impl.t0 t0VarB62 = AbstractC0147y.b(arrayList14, t0VarB61);
                t0VarB62.a(new C0169h(1, u0Var3, 1L));
                AbstractC0147y.i(1, u0Var4, 3L, t0VarB62);
                androidx.camera.core.impl.t0 t0VarB63 = AbstractC0147y.b(arrayList14, t0VarB62);
                t0VarB63.a(new C0169h(1, u0Var3, 1L));
                AbstractC0147y.i(2, u0Var4, 3L, t0VarB63);
                androidx.camera.core.impl.t0 t0VarB64 = AbstractC0147y.b(arrayList14, t0VarB63);
                t0VarB64.a(new C0169h(1, u0Var3, 1L));
                AbstractC0147y.i(2, u0Var3, 1L, t0VarB64);
                androidx.camera.core.impl.t0 t0VarB65 = AbstractC0147y.b(arrayList14, t0VarB64);
                t0VarB65.a(new C0169h(1, u0Var3, 1L));
                u0Var = u0Var7;
                t0VarB65.a(new C0169h(1, u0Var4, 3L));
                AbstractC0147y.i(3, u0Var4, 2L, t0VarB65);
                androidx.camera.core.impl.t0 t0VarB66 = AbstractC0147y.b(arrayList14, t0VarB65);
                t0VarB66.a(new C0169h(1, u0Var3, 1L));
                t0VarB66.a(new C0169h(2, u0Var4, 3L));
                i = i5;
                AbstractC0147y.i(3, u0Var4, 2L, t0VarB66);
                androidx.camera.core.impl.t0 t0VarB67 = AbstractC0147y.b(arrayList14, t0VarB66);
                t0VarB67.a(new C0169h(1, u0Var3, 1L));
                t0VarB67.a(new C0169h(2, u0Var3, 1L));
                AbstractC0147y.i(3, u0Var2, 2L, t0VarB67);
                arrayList14.add(t0VarB67);
                this.h.addAll(arrayList14);
            }
            androidx.camera.camera2.internal.compat.k kVar2 = this.k;
            if (i < 33 || (iArr = (int[]) kVar2.a(CameraCharacteristics.CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES)) == null || iArr.length == 0) {
                z = false;
            } else {
                for (int i6 : iArr) {
                    if (i6 == 2) {
                        z = true;
                        break;
                    }
                }
                z = false;
            }
            if (z && Build.VERSION.SDK_INT >= 33) {
                ArrayList arrayList15 = new ArrayList();
                androidx.camera.core.impl.t0 t0Var13 = new androidx.camera.core.impl.t0();
                u0 u0Var9 = u0Var;
                AbstractC0147y.i(1, u0Var9, 0L, t0Var13);
                androidx.camera.core.impl.t0 t0VarB68 = AbstractC0147y.b(arrayList15, t0Var13);
                AbstractC0147y.i(2, u0Var9, 0L, t0VarB68);
                androidx.camera.core.impl.t0 t0VarB69 = AbstractC0147y.b(arrayList15, t0VarB68);
                t0VarB69.a(new C0169h(1, u0Var9, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB69);
                androidx.camera.core.impl.t0 t0VarB70 = AbstractC0147y.b(arrayList15, t0VarB69);
                t0VarB70.a(new C0169h(2, u0Var9, 0L));
                AbstractC0147y.i(3, u0Var2, 0L, t0VarB70);
                androidx.camera.core.impl.t0 t0VarB71 = AbstractC0147y.b(arrayList15, t0VarB70);
                t0VarB71.a(new C0169h(1, u0Var9, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB71);
                androidx.camera.core.impl.t0 t0VarB72 = AbstractC0147y.b(arrayList15, t0VarB71);
                t0VarB72.a(new C0169h(2, u0Var9, 0L));
                AbstractC0147y.i(2, u0Var2, 0L, t0VarB72);
                androidx.camera.core.impl.t0 t0VarB73 = AbstractC0147y.b(arrayList15, t0VarB72);
                t0VarB73.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var9, 0L, t0VarB73);
                androidx.camera.core.impl.t0 t0VarB74 = AbstractC0147y.b(arrayList15, t0VarB73);
                t0VarB74.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(1, u0Var9, 0L, t0VarB74);
                androidx.camera.core.impl.t0 t0VarB75 = AbstractC0147y.b(arrayList15, t0VarB74);
                t0VarB75.a(new C0169h(1, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var9, 0L, t0VarB75);
                androidx.camera.core.impl.t0 t0VarB76 = AbstractC0147y.b(arrayList15, t0VarB75);
                t0VarB76.a(new C0169h(2, u0Var3, 0L));
                AbstractC0147y.i(2, u0Var9, 0L, t0VarB76);
                arrayList15.add(t0VarB76);
                this.d.addAll(arrayList15);
            }
            b();
        } catch (CameraAccessExceptionCompat e2) {
            throw new CameraUnavailableException(e2);
        }
    }

    public static Size c(StreamConfigurationMap streamConfigurationMap, int i, boolean z) {
        Size[] highResolutionOutputSizes;
        Size[] outputSizes = i == 34 ? streamConfigurationMap.getOutputSizes(SurfaceTexture.class) : streamConfigurationMap.getOutputSizes(i);
        if (outputSizes == null || outputSizes.length == 0) {
            return null;
        }
        androidx.camera.core.impl.utils.c cVar = new androidx.camera.core.impl.utils.c(false);
        Size size = (Size) Collections.max(Arrays.asList(outputSizes), cVar);
        Size size2 = androidx.camera.core.internal.utils.a.a;
        if (z && (highResolutionOutputSizes = streamConfigurationMap.getHighResolutionOutputSizes(i)) != null && highResolutionOutputSizes.length > 0) {
            size2 = (Size) Collections.max(Arrays.asList(highResolutionOutputSizes), cVar);
        }
        return (Size) Collections.max(Arrays.asList(size, size2), cVar);
    }

    public static int e(Range range, Range range2) {
        AbstractC3242q6.h("Ranges must not intersect", (range.contains((Range) range2.getUpper()) || range.contains((Range) range2.getLower())) ? false : true);
        return ((Integer) range.getLower()).intValue() > ((Integer) range2.getUpper()).intValue() ? ((Integer) range.getLower()).intValue() - ((Integer) range2.getUpper()).intValue() : ((Integer) range2.getLower()).intValue() - ((Integer) range.getUpper()).intValue();
    }

    public static int f(Range range) {
        return (((Integer) range.getUpper()).intValue() - ((Integer) range.getLower()).intValue()) + 1;
    }

    public final boolean a(C0126c c0126c, List list) {
        List list2;
        HashMap map = this.e;
        if (map.containsKey(c0126c)) {
            list2 = (List) map.get(c0126c);
        } else {
            ArrayList arrayList = new ArrayList();
            boolean z = c0126c.d;
            int i = c0126c.a;
            if (!z) {
                int i2 = c0126c.b;
                if (i2 == 8) {
                    if (i != 1) {
                        ArrayList arrayList2 = this.a;
                        if (i != 2) {
                            if (c0126c.c) {
                                arrayList2 = this.d;
                            }
                            arrayList.addAll(arrayList2);
                        } else {
                            arrayList.addAll(this.b);
                            arrayList.addAll(arrayList2);
                        }
                    } else {
                        arrayList = this.c;
                    }
                } else if (i2 == 10 && i == 0) {
                    arrayList.addAll(this.f);
                }
            } else if (i == 0) {
                arrayList.addAll(this.g);
            }
            map.put(c0126c, arrayList);
            list2 = arrayList;
        }
        Iterator it2 = list2.iterator();
        boolean z2 = false;
        while (it2.hasNext()) {
            z2 = ((androidx.camera.core.impl.t0) it2.next()).c(list) != null;
            if (z2) {
                break;
            }
        }
        return z2;
    }

    public final void b() throws NumberFormatException {
        Size size;
        Size size2;
        Size size3;
        int i;
        InterfaceC0127d interfaceC0127d;
        CamcorderProfile camcorderProfileB;
        CamcorderProfile camcorderProfileB2;
        Size sizeE = this.u.e();
        try {
            i = Integer.parseInt(this.i);
            interfaceC0127d = this.j;
            camcorderProfileB = null;
            camcorderProfileB2 = interfaceC0127d.g(i, 1) ? interfaceC0127d.b(i, 1) : null;
        } catch (NumberFormatException unused) {
            Size[] outputSizes = ((StreamConfigurationMap) ((com.google.android.gms.internal.instantapps.a) this.k.b().b).b).getOutputSizes(MediaRecorder.class);
            if (outputSizes == null) {
                size = androidx.camera.core.internal.utils.a.c;
            } else {
                Arrays.sort(outputSizes, new androidx.camera.core.impl.utils.c(true));
                for (Size size4 : outputSizes) {
                    int width = size4.getWidth();
                    Size size5 = androidx.camera.core.internal.utils.a.e;
                    if (width <= size5.getWidth() && size4.getHeight() <= size5.getHeight()) {
                        size2 = size4;
                        break;
                    }
                }
                size = androidx.camera.core.internal.utils.a.c;
            }
            size2 = size;
        }
        if (camcorderProfileB2 != null) {
            size2 = new Size(camcorderProfileB2.videoFrameWidth, camcorderProfileB2.videoFrameHeight);
        } else {
            Size size6 = androidx.camera.core.internal.utils.a.c;
            if (interfaceC0127d.g(i, 10)) {
                camcorderProfileB = interfaceC0127d.b(i, 10);
            } else if (interfaceC0127d.g(i, 8)) {
                camcorderProfileB = interfaceC0127d.b(i, 8);
            } else if (interfaceC0127d.g(i, 12)) {
                camcorderProfileB = interfaceC0127d.b(i, 12);
            } else if (interfaceC0127d.g(i, 6)) {
                camcorderProfileB = interfaceC0127d.b(i, 6);
            } else if (interfaceC0127d.g(i, 5)) {
                camcorderProfileB = interfaceC0127d.b(i, 5);
            } else if (interfaceC0127d.g(i, 4)) {
                camcorderProfileB = interfaceC0127d.b(i, 4);
            }
            if (camcorderProfileB == null) {
                size3 = size6;
                this.s = new C0170i(androidx.camera.core.internal.utils.a.b, new HashMap(), sizeE, new HashMap(), size3, new HashMap(), new HashMap());
            }
            size2 = new Size(camcorderProfileB.videoFrameWidth, camcorderProfileB.videoFrameHeight);
        }
        size3 = size2;
        this.s = new C0170i(androidx.camera.core.internal.utils.a.b, new HashMap(), sizeE, new HashMap(), size3, new HashMap(), new HashMap());
    }

    public final List d(C0126c c0126c, List list) {
        C0162c c0162c = e0.a;
        if (c0126c.a != 0 || c0126c.b != 8) {
            return null;
        }
        Iterator it2 = this.h.iterator();
        while (it2.hasNext()) {
            List listC = ((androidx.camera.core.impl.t0) it2.next()).c(list);
            if (listC != null) {
                return listC;
            }
        }
        return null;
    }

    /* JADX WARN: Code restructure failed: missing block: B:367:0x091b, code lost:
    
        r7 = r30;
     */
    /* JADX WARN: Removed duplicated region for block: B:197:0x04cc  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x04de  */
    /* JADX WARN: Removed duplicated region for block: B:320:0x07ef  */
    /* JADX WARN: Removed duplicated region for block: B:440:0x0a73  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:451:0x0aae  */
    /* JADX WARN: Removed duplicated region for block: B:499:0x0bc4  */
    /* JADX WARN: Removed duplicated region for block: B:586:0x0d85  */
    /* JADX WARN: Removed duplicated region for block: B:696:0x04e8 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:728:0x083c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x024a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.util.Pair g(int r35, java.util.ArrayList r36, java.util.HashMap r37, boolean r38, boolean r39) {
        /*
            Method dump skipped, instructions count: 3732
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.f0.g(int, java.util.ArrayList, java.util.HashMap, boolean, boolean):android.util.Pair");
    }

    public final Pair h(int i, ArrayList arrayList, List list, ArrayList arrayList2, ArrayList arrayList3, int i2, HashMap map, HashMap map2) {
        int outputMinFrameDuration;
        ArrayList arrayList4 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            C0158a c0158a = (C0158a) it2.next();
            arrayList4.add(c0158a.a);
            if (map != null) {
                map.put(Integer.valueOf(arrayList4.size() - 1), c0158a);
            }
        }
        for (int i3 = 0; i3 < list.size(); i3++) {
            Size size = (Size) list.get(i3);
            A0 a0 = (A0) arrayList2.get(((Integer) arrayList3.get(i3)).intValue());
            int iO = a0.o();
            arrayList4.add(C0169h.b(i, iO, size, i(iO)));
            if (map2 != null) {
                map2.put(Integer.valueOf(arrayList4.size() - 1), a0);
            }
            try {
                outputMinFrameDuration = (int) (1.0E9d / ((StreamConfigurationMap) this.k.a(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)).getOutputMinFrameDuration(a0.o(), size));
            } catch (Exception unused) {
                outputMinFrameDuration = 0;
            }
            i2 = Math.min(i2, outputMinFrameDuration);
        }
        return new Pair(arrayList4, Integer.valueOf(i2));
    }

    public final C0170i i(int i) {
        StreamConfigurationMap streamConfigurationMap;
        ArrayList arrayList = this.t;
        if (!arrayList.contains(Integer.valueOf(i))) {
            j(this.s.b, androidx.camera.core.internal.utils.a.d, i);
            j(this.s.d, androidx.camera.core.internal.utils.a.f, i);
            HashMap map = this.s.f;
            androidx.camera.camera2.internal.compat.k kVar = this.k;
            Size sizeC = c((StreamConfigurationMap) ((com.google.android.gms.internal.instantapps.a) kVar.b().b).b, i, true);
            if (sizeC != null) {
                map.put(Integer.valueOf(i), sizeC);
            }
            HashMap map2 = this.s.g;
            if (Build.VERSION.SDK_INT >= 31 && this.r && (streamConfigurationMap = (StreamConfigurationMap) kVar.a(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP_MAXIMUM_RESOLUTION)) != null) {
                map2.put(Integer.valueOf(i), c(streamConfigurationMap, i, true));
            }
            arrayList.add(Integer.valueOf(i));
        }
        return this.s;
    }

    public final void j(HashMap map, Size size, int i) {
        if (this.p) {
            Size sizeC = c((StreamConfigurationMap) ((com.google.android.gms.internal.instantapps.a) this.k.b().b).b, i, false);
            Integer numValueOf = Integer.valueOf(i);
            if (sizeC != null) {
                size = (Size) Collections.min(Arrays.asList(size, sizeC), new androidx.camera.core.impl.utils.c(false));
            }
            map.put(numValueOf, size);
        }
    }
}
