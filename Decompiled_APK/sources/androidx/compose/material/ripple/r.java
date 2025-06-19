package androidx.compose.material.ripple;

import android.content.Context;
import android.media.Image;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import androidx.appcompat.app.L;
import androidx.collection.C0219q;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.G;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.dynamite.DynamiteModule$LoadingException;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractBinderC3118d;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3217o;
import com.google.android.gms.internal.mlkit_vision_barcode.C3100b;
import com.google.android.gms.internal.mlkit_vision_barcode.C3109c;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.google.android.gms.internal.mlkit_vision_barcode.InterfaceC3127e;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.internal.mlkit_vision_barcode.zzah;
import com.google.android.gms.internal.mlkit_vision_barcode.zzan;
import com.google.android.gms.internal.mlkit_vision_barcode.zzu;
import com.google.android.gms.internal.mlkit_vision_common.D3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3715s;
import com.google.mlkit.common.MlKitException;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import okhttp3.H;
import okhttp3.I;
import okhttp3.internal.http2.ConnectionShutdownException;
import okhttp3.internal.http2.StreamResetException;
import okio.AbstractC5085b;

/* loaded from: classes.dex */
public final class r implements com.google.mlkit.vision.barcode.internal.f {
    public boolean a;
    public Object b;
    public Object c = AbstractC0240f.a(DefinitionKt.NO_Float_VALUE);
    public Object d = new ArrayList();
    public Object e;

    /* JADX WARN: Multi-variable type inference failed */
    public r(boolean z, Function0 function0) {
        this.a = z;
        this.b = (kotlin.jvm.internal.r) function0;
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public boolean a() throws MlKitException {
        InterfaceC3127e c3109c;
        Context context = (Context) this.b;
        if (((C3100b) this.e) != null) {
            return false;
        }
        try {
            IBinder iBinderB = com.google.android.gms.dynamite.c.c(context, com.google.android.gms.dynamite.c.b, "com.google.android.gms.vision.dynamite").b("com.google.android.gms.vision.barcode.ChimeraNativeBarcodeDetectorCreator");
            int i = AbstractBinderC3118d.b;
            if (iBinderB == null) {
                c3109c = null;
            } else {
                IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetectorCreator");
                c3109c = iInterfaceQueryLocalInterface instanceof InterfaceC3127e ? (InterfaceC3127e) iInterfaceQueryLocalInterface : new C3109c(iBinderB, "com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetectorCreator", 5);
            }
            C3100b c3100bH4 = ((C3109c) c3109c).h4(new com.google.android.gms.dynamic.b(context), (zzah) this.c);
            this.e = c3100bH4;
            J7 j7 = (J7) this.d;
            if (c3100bH4 == null && !this.a) {
                Feature[] featureArr = com.google.mlkit.common.sdkinternal.h.a;
                com.google.android.gms.internal.mlkit_common.b bVar = com.google.android.gms.internal.mlkit_common.d.b;
                Object[] objArr = {"barcode"};
                D3.a(1, objArr);
                com.google.mlkit.common.sdkinternal.h.a(context, new com.google.android.gms.internal.mlkit_common.g(objArr, 1));
                this.a = true;
                com.google.mlkit.vision.barcode.internal.a.b(j7, EnumC3290w5.OPTIONAL_MODULE_NOT_AVAILABLE);
                throw new MlKitException("Waiting for the barcode module to be downloaded. Please wait.", 14);
            }
            com.google.mlkit.vision.barcode.internal.a.b(j7, EnumC3290w5.NO_ERROR);
            return false;
        } catch (RemoteException e) {
            throw new MlKitException("Failed to create legacy barcode detector.", e);
        } catch (DynamiteModule$LoadingException e2) {
            throw new MlKitException("Failed to load deprecated vision dynamite module.", e2);
        }
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public ArrayList b(com.google.mlkit.vision.common.a aVar) throws MlKitException {
        zzu[] zzuVarArrH4;
        if (((C3100b) this.e) == null) {
            a();
        }
        C3100b c3100b = (C3100b) this.e;
        if (c3100b == null) {
            throw new MlKitException("Error initializing the legacy barcode scanner.", 14);
        }
        zzan zzanVar = new zzan(aVar.c, 0L, aVar.d, 0, com.google.android.gms.internal.mlkit_vision_document_scanner.r.a(aVar.e));
        try {
            int i = aVar.f;
            if (i == -1) {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(aVar.a);
                Parcel parcelF3 = c3100b.f3();
                AbstractC3217o.a(parcelF3, bVar);
                parcelF3.writeInt(1);
                zzanVar.writeToParcel(parcelF3, 0);
                Parcel parcelP3 = c3100b.p3(2, parcelF3);
                zzu[] zzuVarArr = (zzu[]) parcelP3.createTypedArray(zzu.CREATOR);
                parcelP3.recycle();
                zzuVarArrH4 = zzuVarArr;
            } else if (i == 17) {
                zzuVarArrH4 = c3100b.h4(new com.google.android.gms.dynamic.b(null), zzanVar);
            } else if (i == 35) {
                Image.Plane[] planeArrA = aVar.a();
                u.h(planeArrA);
                zzanVar.a = planeArrA[0].getRowStride();
                zzuVarArrH4 = c3100b.h4(new com.google.android.gms.dynamic.b(planeArrA[0].getBuffer()), zzanVar);
            } else {
                if (i != 842094169) {
                    throw new MlKitException("Unsupported image format: " + aVar.f, 3);
                }
                zzuVarArrH4 = c3100b.h4(new com.google.android.gms.dynamic.b(AbstractC3715s.a(aVar)), zzanVar);
            }
            ArrayList arrayList = new ArrayList();
            for (zzu zzuVar : zzuVarArrH4) {
                arrayList.add(new com.google.mlkit.vision.barcode.common.a(new com.airbnb.lottie.network.c(zzuVar, 28)));
            }
            return arrayList;
        } catch (RemoteException e) {
            throw new MlKitException("Failed to detect with legacy barcode detector", e);
        }
    }

    public IOException c(boolean z, boolean z2, IOException ioe) {
        if (ioe != null) {
            n(ioe);
        }
        okhttp3.internal.connection.g call = (okhttp3.internal.connection.g) this.b;
        if (z2) {
            if (ioe != null) {
                Intrinsics.checkNotNullParameter(call, "call");
                Intrinsics.checkNotNullParameter(ioe, "ioe");
            } else {
                Intrinsics.checkNotNullParameter(call, "call");
            }
        }
        if (z) {
            if (ioe != null) {
                Intrinsics.checkNotNullParameter(call, "call");
                Intrinsics.checkNotNullParameter(ioe, "ioe");
            } else {
                Intrinsics.checkNotNullParameter(call, "call");
            }
        }
        return call.i(this, z2, z, ioe);
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(java.lang.String r10, long r11, long r13, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r9 = this;
            boolean r0 = r15 instanceof com.quizlet.features.infra.folder.menu.data.i
            if (r0 == 0) goto L14
            r0 = r15
            com.quizlet.features.infra.folder.menu.data.i r0 = (com.quizlet.features.infra.folder.menu.data.i) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r8 = r0
            goto L1a
        L14:
            com.quizlet.features.infra.folder.menu.data.i r0 = new com.quizlet.features.infra.folder.menu.data.i
            r0.<init>(r9, r15)
            goto L12
        L1a:
            java.lang.Object r15 = r8.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.m
            r2 = 1
            if (r1 == 0) goto L37
            if (r1 != r2) goto L2f
            androidx.compose.material.ripple.r r10 = r8.j
            androidx.glance.appwidget.protobuf.Z.e(r15)
            kotlin.r r15 = (kotlin.r) r15
            java.lang.Object r11 = r15.a
            goto L4f
        L2f:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            r8.j = r9
            r8.m = r2
            java.lang.Object r15 = r9.e
            r1 = r15
            com.google.android.gms.measurement.internal.J r1 = (com.google.android.gms.measurement.internal.J) r1
            r3 = 0
            r2 = r10
            r4 = r11
            r6 = r13
            java.lang.Object r11 = r1.f(r2, r3, r4, r6, r8)
            if (r11 != r0) goto L4e
            return r0
        L4e:
            r10 = r9
        L4f:
            kotlin.p r12 = kotlin.r.b
            boolean r12 = r11 instanceof kotlin.q
            if (r12 != 0) goto L5e
            com.quizlet.data.model.d0 r11 = (com.quizlet.data.model.AbstractC4119d0) r11
            java.lang.String r12 = "null cannot be cast to non-null type com.quizlet.data.model.CreatedFolder"
            kotlin.jvm.internal.Intrinsics.e(r11, r12)
            com.quizlet.data.model.CreatedFolder r11 = (com.quizlet.data.model.CreatedFolder) r11
        L5e:
            boolean r12 = r11 instanceof kotlin.q
            if (r12 != 0) goto L7b
            r12 = r11
            com.quizlet.data.model.CreatedFolder r12 = (com.quizlet.data.model.CreatedFolder) r12
            com.quizlet.data.model.u r0 = new com.quizlet.data.model.u
            long r1 = r12.a()
            java.lang.String r3 = r12.g()
            r5 = 0
            r4 = 0
            r0.<init>(r1, r3, r4, r5)
            java.lang.Object r10 = r10.d
            java.util.ArrayList r10 = (java.util.ArrayList) r10
            r10.add(r0)
        L7b:
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.ripple.r.d(java.lang.String, long, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void e(G g, float f, long j) {
        float fFloatValue = ((Number) ((C0238e) this.c).d()).floatValue();
        if (fFloatValue > DefinitionKt.NO_Float_VALUE) {
            long jB = C0861v.b(j, fFloatValue);
            if (!this.a) {
                androidx.compose.ui.graphics.drawscope.d.V(g, jB, f, 0L, null, 124);
                return;
            }
            androidx.compose.ui.graphics.drawscope.b bVar = g.a;
            float fD = androidx.compose.ui.geometry.e.d(bVar.g());
            float fB = androidx.compose.ui.geometry.e.b(bVar.g());
            com.quizlet.data.repository.folderset.c cVar = bVar.b;
            long jR = cVar.r();
            cVar.o().e();
            try {
                ((L) cVar.b).H(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, fD, fB, 1);
                androidx.compose.ui.graphics.drawscope.d.V(g, jB, f, 0L, null, 124);
            } finally {
                d0.y(cVar, jR);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r5, com.quizlet.generated.enums.y1 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.infra.folder.menu.data.j
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.infra.folder.menu.data.j r0 = (com.quizlet.features.infra.folder.menu.data.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.menu.data.j r0 = new com.quizlet.features.infra.folder.menu.data.j
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            androidx.compose.material.ripple.r r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r6 = r7.a
            goto L54
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            boolean r7 = r4.a
            if (r7 == 0) goto L43
            kotlin.p r5 = kotlin.r.b
            java.lang.Object r5 = r4.d
            java.util.ArrayList r5 = (java.util.ArrayList) r5
            return r5
        L43:
            r0.j = r4
            r0.m = r3
            java.lang.Object r7 = r4.b
            com.google.firebase.messaging.p r7 = (com.google.firebase.messaging.p) r7
            r2 = 0
            java.lang.Object r6 = r7.w(r5, r6, r2, r0)
            if (r6 != r1) goto L53
            return r1
        L53:
            r5 = r4
        L54:
            kotlin.p r7 = kotlin.r.b
            boolean r7 = r6 instanceof kotlin.q
            if (r7 != 0) goto L6d
            r7 = r6
            java.util.List r7 = (java.util.List) r7
            java.lang.Object r0 = r5.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            r0.clear()
            java.lang.Object r0 = r5.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            r0.addAll(r7)
            r5.a = r3
        L6d:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.ripple.r.f(java.lang.String, com.quizlet.generated.enums.y1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(long r6, com.quizlet.generated.enums.y1 r8, java.lang.String r9, kotlin.coroutines.jvm.internal.c r10) {
        /*
            r5 = this;
            r0 = 1
            boolean r1 = r10 instanceof com.quizlet.features.infra.folder.menu.data.k
            if (r1 == 0) goto L14
            r1 = r10
            com.quizlet.features.infra.folder.menu.data.k r1 = (com.quizlet.features.infra.folder.menu.data.k) r1
            int r2 = r1.n
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            r4 = r2 & r3
            if (r4 == 0) goto L14
            int r2 = r2 - r3
            r1.n = r2
            goto L19
        L14:
            com.quizlet.features.infra.folder.menu.data.k r1 = new com.quizlet.features.infra.folder.menu.data.k
            r1.<init>(r5, r10)
        L19:
            java.lang.Object r10 = r1.l
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            int r3 = r1.n
            if (r3 == 0) goto L37
            if (r3 != r0) goto L2f
            long r6 = r1.k
            androidx.compose.material.ripple.r r8 = r1.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlin.r r10 = (kotlin.r) r10
            java.lang.Object r9 = r10.a
            goto L51
        L2f:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            java.lang.Long r10 = new java.lang.Long
            r10.<init>(r6)
            r1.j = r5
            r1.k = r6
            r1.n = r0
            java.lang.Object r3 = r5.b
            com.google.firebase.messaging.p r3 = (com.google.firebase.messaging.p) r3
            java.lang.Object r9 = r3.w(r9, r8, r10, r1)
            if (r9 != r2) goto L50
            return r2
        L50:
            r8 = r5
        L51:
            kotlin.p r10 = kotlin.r.b
            boolean r10 = r9 instanceof kotlin.q
            if (r10 != 0) goto L67
            java.util.List r9 = (java.util.List) r9     // Catch: java.lang.Throwable -> L60
            java.lang.Object r9 = kotlin.collections.CollectionsKt.L(r9)     // Catch: java.lang.Throwable -> L60
            com.quizlet.data.model.u r9 = (com.quizlet.data.model.C4169u) r9     // Catch: java.lang.Throwable -> L60
            goto L67
        L60:
            r9 = move-exception
            kotlin.p r10 = kotlin.r.b
            kotlin.q r9 = androidx.glance.appwidget.protobuf.Z.b(r9)
        L67:
            boolean r10 = r9 instanceof kotlin.q
            if (r10 != 0) goto L94
            r10 = r9
            com.quizlet.data.model.u r10 = (com.quizlet.data.model.C4169u) r10
            boolean r1 = r8.a
            if (r1 == 0) goto L94
            java.lang.Object r8 = r8.d
            java.util.ArrayList r8 = (java.util.ArrayList) r8
            java.util.Iterator r1 = r8.iterator()
            r2 = 0
        L7b:
            boolean r3 = r1.hasNext()
            if (r3 == 0) goto L90
            java.lang.Object r3 = r1.next()
            com.quizlet.data.model.u r3 = (com.quizlet.data.model.C4169u) r3
            long r3 = r3.a
            int r3 = (r3 > r6 ? 1 : (r3 == r6 ? 0 : -1))
            if (r3 != 0) goto L8e
            goto L91
        L8e:
            int r2 = r2 + r0
            goto L7b
        L90:
            r2 = -1
        L91:
            r8.set(r2, r10)
        L94:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.ripple.r.g(long, com.quizlet.generated.enums.y1, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Type inference failed for: r5v4, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public void h(androidx.compose.foundation.interaction.j jVar, C c) {
        boolean z = jVar instanceof androidx.compose.foundation.interaction.h;
        ArrayList arrayList = (ArrayList) this.d;
        if (z) {
            arrayList.add(jVar);
        } else if (jVar instanceof androidx.compose.foundation.interaction.i) {
            arrayList.remove(((androidx.compose.foundation.interaction.i) jVar).a);
        } else if (jVar instanceof androidx.compose.foundation.interaction.d) {
            arrayList.add(jVar);
        } else if (jVar instanceof androidx.compose.foundation.interaction.e) {
            arrayList.remove(((androidx.compose.foundation.interaction.e) jVar).a);
        } else if (jVar instanceof androidx.compose.foundation.interaction.b) {
            arrayList.add(jVar);
        } else if (jVar instanceof androidx.compose.foundation.interaction.c) {
            arrayList.remove(((androidx.compose.foundation.interaction.c) jVar).a);
        } else if (!(jVar instanceof androidx.compose.foundation.interaction.a)) {
            return;
        } else {
            arrayList.remove(((androidx.compose.foundation.interaction.a) jVar).a);
        }
        androidx.compose.foundation.interaction.j jVar2 = (androidx.compose.foundation.interaction.j) CollectionsKt.V(arrayList);
        if (Intrinsics.b((androidx.compose.foundation.interaction.j) this.e, jVar2)) {
            return;
        }
        if (jVar2 != null) {
            f fVar = (f) ((kotlin.jvm.internal.r) this.b).invoke();
            float f = z ? fVar.c : jVar instanceof androidx.compose.foundation.interaction.d ? fVar.b : jVar instanceof androidx.compose.foundation.interaction.b ? fVar.a : DefinitionKt.NO_Float_VALUE;
            K0 k0 = k.a;
            boolean z2 = jVar2 instanceof androidx.compose.foundation.interaction.h;
            K0 k02 = k.a;
            if (!z2 && ((jVar2 instanceof androidx.compose.foundation.interaction.d) || (jVar2 instanceof androidx.compose.foundation.interaction.b))) {
                k02 = new K0(45, androidx.compose.animation.core.C.d, 2);
            }
            E.A(c, null, null, new p(this, f, k02, null), 3);
        } else {
            androidx.compose.foundation.interaction.j jVar3 = (androidx.compose.foundation.interaction.j) this.e;
            K0 k03 = k.a;
            boolean z3 = jVar3 instanceof androidx.compose.foundation.interaction.h;
            K0 k04 = k.a;
            if (!z3 && !(jVar3 instanceof androidx.compose.foundation.interaction.d) && (jVar3 instanceof androidx.compose.foundation.interaction.b)) {
                k04 = new K0(150, androidx.compose.animation.core.C.d, 2);
            }
            E.A(c, null, null, new q(this, k04, null), 3);
        }
        this.e = jVar2;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object i(com.quizlet.data.interactor.folderstudymaterial.g r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.infra.folder.menu.data.l
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.infra.folder.menu.data.l r0 = (com.quizlet.features.infra.folder.menu.data.l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.infra.folder.menu.data.l r0 = new com.quizlet.features.infra.folder.menu.data.l
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            androidx.compose.material.ripple.r r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.r r6 = (kotlin.r) r6
            java.lang.Object r6 = r6.a
            goto L48
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.m = r3
            java.lang.Object r6 = r4.c
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = (com.onetrust.otpublishers.headless.UI.fragment.q) r6
            java.lang.Object r6 = r6.q(r5, r0)
            if (r6 != r1) goto L47
            return r1
        L47:
            r5 = r4
        L48:
            kotlin.p r0 = kotlin.r.b
            boolean r0 = r6 instanceof kotlin.q
            if (r0 != 0) goto L5b
            r0 = r6
            com.quizlet.data.interactor.folderstudymaterial.h r0 = (com.quizlet.data.interactor.folderstudymaterial.h) r0
            java.lang.Object r0 = r5.d
            java.util.ArrayList r0 = (java.util.ArrayList) r0
            r0.clear()
            r0 = 0
            r5.a = r0
        L5b:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material.ripple.r.i(com.quizlet.data.interactor.folderstudymaterial.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public I j(H response) throws IOException {
        okhttp3.internal.http.d dVar = (okhttp3.internal.http.d) this.d;
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            String strA = H.a("Content-Type", response);
            long jG = dVar.g(response);
            return new I(strA, jG, AbstractC5085b.c(new okhttp3.internal.connection.c(this, dVar.c(response), jG)));
        } catch (IOException ioe) {
            okhttp3.internal.connection.g call = (okhttp3.internal.connection.g) this.b;
            Intrinsics.checkNotNullParameter(call, "call");
            Intrinsics.checkNotNullParameter(ioe, "ioe");
            n(ioe);
            throw ioe;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int k(com.quizlet.data.repository.qclass.c cVar, C0971v c0971v, boolean z) {
        Object[] objArr;
        com.quizlet.data.repository.folderwithcreator.e eVar;
        int i;
        androidx.compose.ui.node.r rVar = (androidx.compose.ui.node.r) this.e;
        if (this.a) {
            return 0;
        }
        try {
            this.a = true;
            C3083y1 c3083y1Z = ((com.airbnb.lottie.network.c) this.d).z(cVar, c0971v);
            C0219q c0219q = (C0219q) c3083y1Z.c;
            int i2 = c0219q.i();
            for (int i3 = 0; i3 < i2; i3++) {
                androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) c0219q.k(i3);
                if (!nVar.d && !nVar.h) {
                }
                objArr = false;
                break;
            }
            objArr = true;
            int i4 = c0219q.i();
            int i5 = 0;
            while (true) {
                eVar = (com.quizlet.data.repository.folderwithcreator.e) this.c;
                if (i5 >= i4) {
                    break;
                }
                androidx.compose.ui.input.pointer.n nVar2 = (androidx.compose.ui.input.pointer.n) c0219q.k(i5);
                if (objArr != false || androidx.compose.ui.input.pointer.l.a(nVar2)) {
                    ((androidx.compose.ui.node.E) this.b).x(nVar2.c, (androidx.compose.ui.node.r) this.e, nVar2.i == 1, true);
                    if (!rVar.isEmpty()) {
                        eVar.b(nVar2.a, rVar, androidx.compose.ui.input.pointer.l.a(nVar2));
                        rVar.clear();
                    }
                }
                i5++;
            }
            ((androidx.webkit.internal.p) eVar.c).u();
            boolean zD = eVar.d(c3083y1Z, z);
            if (!c3083y1Z.b) {
                int i6 = c0219q.i();
                for (int i7 = 0; i7 < i6; i7++) {
                    androidx.compose.ui.input.pointer.n nVar3 = (androidx.compose.ui.input.pointer.n) c0219q.k(i7);
                    if (!androidx.compose.ui.geometry.b.b(androidx.compose.ui.input.pointer.l.g(nVar3, true), 0L) && nVar3.b()) {
                        i = 2;
                        break;
                    }
                }
            }
            i = 0;
            int i8 = (zD ? 1 : 0) | i;
            this.a = false;
            return i8;
        } catch (Throwable th) {
            this.a = false;
            throw th;
        }
    }

    public void l() {
        if (this.a) {
            return;
        }
        ((C0219q) ((com.airbnb.lottie.network.c) this.d).b).b();
        com.quizlet.data.repository.folderwithcreator.e eVar = (com.quizlet.data.repository.folderwithcreator.e) this.c;
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) ((androidx.webkit.internal.p) eVar.c).b;
        int i = bVar.c;
        if (i > 0) {
            Object[] objArr = bVar.a;
            int i2 = 0;
            do {
                ((androidx.compose.ui.input.pointer.e) objArr[i2]).A();
                i2++;
            } while (i2 < i);
        }
        ((androidx.compose.runtime.collection.b) ((androidx.webkit.internal.p) eVar.c).b).i();
    }

    public okhttp3.G m(boolean z) throws IOException {
        try {
            okhttp3.G gD = ((okhttp3.internal.http.d) this.d).d(z);
            if (gD != null) {
                Intrinsics.checkNotNullParameter(this, "deferredTrailers");
                gD.m = this;
            }
            return gD;
        } catch (IOException ioe) {
            okhttp3.internal.connection.g call = (okhttp3.internal.connection.g) this.b;
            Intrinsics.checkNotNullParameter(call, "call");
            Intrinsics.checkNotNullParameter(ioe, "ioe");
            n(ioe);
            throw ioe;
        }
    }

    public void n(IOException iOException) {
        this.a = true;
        ((androidx.constraintlayout.core.motion.utils.l) this.c).f(iOException);
        okhttp3.internal.connection.i iVarE = ((okhttp3.internal.http.d) this.d).e();
        okhttp3.internal.connection.g call = (okhttp3.internal.connection.g) this.b;
        synchronized (iVarE) {
            try {
                Intrinsics.checkNotNullParameter(call, "call");
                if (!(iOException instanceof StreamResetException)) {
                    if (!(iVarE.g != null) || (iOException instanceof ConnectionShutdownException)) {
                        iVarE.j = true;
                        if (iVarE.m == 0) {
                            okhttp3.internal.connection.i.d(call.a, iVarE.b, iOException);
                            iVarE.l++;
                        }
                    }
                } else if (((StreamResetException) iOException).a == okhttp3.internal.http2.a.REFUSED_STREAM) {
                    int i = iVarE.n + 1;
                    iVarE.n = i;
                    if (i > 1) {
                        iVarE.j = true;
                        iVarE.l++;
                    }
                } else if (((StreamResetException) iOException).a != okhttp3.internal.http2.a.CANCEL || !call.o) {
                    iVarE.j = true;
                    iVarE.l++;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.mlkit.vision.barcode.internal.f
    public void zzb() {
        C3100b c3100b = (C3100b) this.e;
        if (c3100b != null) {
            try {
                c3100b.v3(3, c3100b.f3());
            } catch (RemoteException e) {
                Log.e("LegacyBarcodeScanner", "Failed to release legacy barcode detector.", e);
            }
            this.e = null;
        }
    }
}
