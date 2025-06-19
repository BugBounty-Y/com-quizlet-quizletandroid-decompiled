package com.google.mlkit.vision.barcode.internal;

import android.content.Context;
import android.graphics.Bitmap;
import android.media.Image;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.Log;
import androidx.webkit.internal.p;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.moduleinstall.ModuleAvailabilityResponse;
import com.google.android.gms.dynamite.DynamiteModule$LoadingException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3217o;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3292x;
import com.google.android.gms.internal.mlkit_vision_barcode.B;
import com.google.android.gms.internal.mlkit_vision_barcode.C3276v;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.internal.mlkit_vision_barcode.O7;
import com.google.android.gms.internal.mlkit_vision_barcode.P7;
import com.google.android.gms.internal.mlkit_vision_barcode.Q7;
import com.google.android.gms.internal.mlkit_vision_barcode.R7;
import com.google.android.gms.internal.mlkit_vision_barcode.zzyb;
import com.google.android.gms.internal.mlkit_vision_barcode.zzyd;
import com.google.android.gms.internal.mlkit_vision_barcode.zzyu;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.r;
import com.google.android.gms.tasks.m;
import com.google.mlkit.common.MlKitException;
import com.google.mlkit.common.sdkinternal.h;
import com.google.mlkit.common.sdkinternal.n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

/* loaded from: classes2.dex */
public final class g implements f {
    public static final B h = AbstractC3292x.h("com.google.android.gms.vision.barcode", "com.google.android.gms.tflite_dynamite");
    public boolean a;
    public boolean b;
    public boolean c;
    public final Context d;
    public final com.google.mlkit.vision.barcode.b e;
    public final J7 f;
    public O7 g;

    public g(Context context, com.google.mlkit.vision.barcode.b bVar, J7 j7) {
        this.d = context;
        this.e = bVar;
        this.f = j7;
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public final boolean a() throws MlKitException {
        boolean z = false;
        if (this.g != null) {
            return this.b;
        }
        Context context = this.d;
        boolean z2 = com.google.android.gms.dynamite.c.a(context, "com.google.mlkit.dynamite.barcode") > 0;
        J7 j7 = this.f;
        if (z2) {
            this.b = true;
            try {
                this.g = c(com.google.android.gms.dynamite.c.c, "com.google.mlkit.dynamite.barcode", "com.google.mlkit.vision.barcode.bundled.internal.ThickBarcodeScannerCreator");
            } catch (RemoteException e) {
                throw new MlKitException("Failed to create thick barcode scanner.", e);
            } catch (DynamiteModule$LoadingException e2) {
                throw new MlKitException("Failed to load the bundled barcode module.", e2);
            }
        } else {
            this.b = false;
            Feature[] featureArr = h.a;
            com.google.android.gms.common.c.b.getClass();
            int iA = com.google.android.gms.common.c.a(context);
            B b = h;
            if (iA >= 221500000) {
                try {
                    m mVarD = new com.google.android.gms.common.moduleinstall.internal.d(context).d(new n(h.c(h.g, b), 1));
                    com.google.mlkit.common.internal.model.a aVar = new com.google.mlkit.common.internal.model.a(20);
                    mVarD.getClass();
                    mVarD.c(com.google.android.gms.tasks.g.a, aVar);
                    z = ((ModuleAvailabilityResponse) S3.e(mVarD)).a;
                } catch (InterruptedException | ExecutionException e3) {
                    Log.e("OptionalModuleUtils", "Failed to complete the task of features availability check", e3);
                }
            } else {
                try {
                    C3276v c3276vListIterator = b.listIterator(0);
                    while (c3276vListIterator.hasNext()) {
                        com.google.android.gms.dynamite.c.c(context, com.google.android.gms.dynamite.c.b, (String) c3276vListIterator.next());
                    }
                    z = true;
                } catch (DynamiteModule$LoadingException unused) {
                }
            }
            if (!z) {
                if (!this.c) {
                    h.a(context, AbstractC3292x.h("barcode", "tflite_dynamite"));
                    this.c = true;
                }
                a.b(j7, EnumC3290w5.OPTIONAL_MODULE_NOT_AVAILABLE);
                throw new MlKitException("Waiting for the barcode module to be downloaded. Please wait.", 14);
            }
            try {
                this.g = c(com.google.android.gms.dynamite.c.b, "com.google.android.gms.vision.barcode", "com.google.android.gms.vision.barcode.mlkit.BarcodeScannerCreator");
            } catch (RemoteException | DynamiteModule$LoadingException e4) {
                a.b(j7, EnumC3290w5.OPTIONAL_MODULE_INIT_ERROR);
                throw new MlKitException("Failed to create thin barcode scanner.", e4);
            }
        }
        a.b(j7, EnumC3290w5.NO_ERROR);
        return this.b;
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public final ArrayList b(com.google.mlkit.vision.common.a aVar) throws MlKitException {
        com.google.android.gms.dynamic.b bVar;
        if (this.g == null) {
            a();
        }
        O7 o7 = this.g;
        u.h(o7);
        if (!this.a) {
            try {
                o7.v3(1, o7.f3());
                this.a = true;
            } catch (RemoteException e) {
                throw new MlKitException("Failed to init barcode scanner.", e);
            }
        }
        int rowStride = aVar.c;
        if (aVar.f == 35) {
            Image.Plane[] planeArrA = aVar.a();
            u.h(planeArrA);
            rowStride = planeArrA[0].getRowStride();
        }
        zzyu zzyuVar = new zzyu(aVar.f, SystemClock.elapsedRealtime(), rowStride, aVar.d, r.a(aVar.e));
        int i = aVar.f;
        if (i != -1) {
            if (i != 17) {
                if (i == 35) {
                    bVar = new com.google.android.gms.dynamic.b(aVar.b != null ? (Image) aVar.b.a : null);
                } else if (i != 842094169) {
                    throw new MlKitException(android.support.v4.media.session.a.f(aVar.f, "Unsupported image format: "), 3);
                }
            }
            u.h(null);
            throw null;
        }
        Bitmap bitmap = aVar.a;
        u.h(bitmap);
        bVar = new com.google.android.gms.dynamic.b(bitmap);
        try {
            Parcel parcelF3 = o7.f3();
            AbstractC3217o.a(parcelF3, bVar);
            parcelF3.writeInt(1);
            zzyuVar.writeToParcel(parcelF3, 0);
            Parcel parcelP3 = o7.p3(3, parcelF3);
            ArrayList arrayListCreateTypedArrayList = parcelP3.createTypedArrayList(zzyb.CREATOR);
            parcelP3.recycle();
            ArrayList arrayList = new ArrayList();
            Iterator it2 = arrayListCreateTypedArrayList.iterator();
            while (it2.hasNext()) {
                arrayList.add(new com.google.mlkit.vision.barcode.common.a(new p((zzyb) it2.next(), 26)));
            }
            return arrayList;
        } catch (RemoteException e2) {
            throw new MlKitException("Failed to run barcode scanner.", e2);
        }
    }

    public final O7 c(com.google.android.gms.dynamite.b bVar, String str, String str2) {
        R7 p7;
        Context context = this.d;
        IBinder iBinderB = com.google.android.gms.dynamite.c.c(context, bVar, str).b(str2);
        int i = Q7.b;
        O7 o7 = null;
        if (iBinderB == null) {
            p7 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.mlkit.vision.barcode.aidls.IBarcodeScannerCreator");
            p7 = iInterfaceQueryLocalInterface instanceof R7 ? (R7) iInterfaceQueryLocalInterface : new P7(iBinderB, "com.google.mlkit.vision.barcode.aidls.IBarcodeScannerCreator", 5);
        }
        com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(context);
        zzyd zzydVar = new zzyd(this.e.a, false);
        P7 p72 = (P7) p7;
        Parcel parcelF3 = p72.f3();
        AbstractC3217o.a(parcelF3, bVar2);
        parcelF3.writeInt(1);
        zzydVar.writeToParcel(parcelF3, 0);
        Parcel parcelP3 = p72.p3(1, parcelF3);
        IBinder strongBinder = parcelP3.readStrongBinder();
        if (strongBinder != null) {
            IInterface iInterfaceQueryLocalInterface2 = strongBinder.queryLocalInterface("com.google.mlkit.vision.barcode.aidls.IBarcodeScanner");
            o7 = iInterfaceQueryLocalInterface2 instanceof O7 ? (O7) iInterfaceQueryLocalInterface2 : new O7(strongBinder, "com.google.mlkit.vision.barcode.aidls.IBarcodeScanner", 5);
        }
        parcelP3.recycle();
        return o7;
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public final void zzb() {
        O7 o7 = this.g;
        if (o7 != null) {
            try {
                o7.v3(2, o7.f3());
            } catch (RemoteException e) {
                Log.e("DecoupledBarcodeScanner", "Failed to release barcode scanner.", e);
            }
            this.g = null;
            this.a = false;
        }
    }
}
