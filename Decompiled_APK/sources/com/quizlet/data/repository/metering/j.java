package com.quizlet.data.repository.metering;

import android.content.Context;
import androidx.lifecycle.A0;
import androidx.lifecycle.B0;
import androidx.lifecycle.C;
import androidx.lifecycle.p0;
import androidx.lifecycle.s0;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Ai;
import com.google.android.gms.internal.ads.C2058fh;
import com.google.android.gms.internal.ads.C2146hh;
import com.google.android.gms.internal.ads.C2332lw;
import com.google.android.gms.internal.ads.InterfaceC1965db;
import com.google.android.gms.internal.ads.Pw;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.zzdgh;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.generated.enums.P;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Iterator;
import kotlin.collections.B;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import okhttp3.A;
import okhttp3.z;
import retrofit2.C5177b;

/* loaded from: classes2.dex */
public final class j implements a, Ai, OTCallback {
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ j() {
        this.a = null;
        this.b = null;
        this.c = null;
        this.d = C2332lw.h;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable b(com.quizlet.data.repository.metering.j r7, com.quizlet.data.repository.metering.a r8, long r9, java.lang.Long r11, com.quizlet.generated.enums.P r12, java.lang.String r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r7.getClass()
            boolean r0 = r14 instanceof com.quizlet.data.repository.metering.g
            if (r0 == 0) goto L17
            r0 = r14
            com.quizlet.data.repository.metering.g r0 = (com.quizlet.data.repository.metering.g) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L17
            int r1 = r1 - r2
            r0.n = r1
        L15:
            r6 = r0
            goto L1d
        L17:
            com.quizlet.data.repository.metering.g r0 = new com.quizlet.data.repository.metering.g
            r0.<init>(r7, r14)
            goto L15
        L1d:
            java.lang.Object r14 = r6.l
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.n
            r2 = 1
            if (r1 == 0) goto L3b
            if (r1 != r2) goto L33
            java.lang.String r13 = r6.k
            com.quizlet.data.repository.metering.j r7 = r6.j
            androidx.glance.appwidget.protobuf.Z.e(r14)     // Catch: java.lang.Exception -> L30
            goto L4f
        L30:
            r0 = move-exception
            r8 = r0
            goto L52
        L33:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r6.j = r7     // Catch: java.lang.Exception -> L30
            r6.k = r13     // Catch: java.lang.Exception -> L30
            r6.n = r2     // Catch: java.lang.Exception -> L30
            r1 = r8
            r2 = r9
            r4 = r11
            r5 = r12
            java.lang.Object r14 = r1.a(r2, r4, r5, r6)     // Catch: java.lang.Exception -> L30
            if (r14 != r0) goto L4f
            return r0
        L4f:
            com.quizlet.data.model.w0 r14 = (com.quizlet.data.model.InterfaceC4176w0) r14     // Catch: java.lang.Exception -> L30
            return r14
        L52:
            java.lang.Object r7 = r7.c
            org.slf4j.b r7 = (org.slf4j.b) r7
            java.lang.String r8 = r8.getMessage()
            java.lang.StringBuilder r9 = new java.lang.StringBuilder
            r9.<init>()
            r9.append(r13)
            java.lang.String r10 = " error trying to fetch MeteringInfo: "
            r9.append(r10)
            r9.append(r8)
            java.lang.String r8 = r9.toString()
            r7.m(r8)
            r7 = 0
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.metering.j.b(com.quizlet.data.repository.metering.j, com.quizlet.data.repository.metering.a, long, java.lang.Long, com.quizlet.generated.enums.P, java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x006a, code lost:
    
        if (r8 == r1) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(com.quizlet.data.repository.metering.j r5, com.quizlet.data.model.InterfaceC4176w0 r6, com.quizlet.data.model.InterfaceC4176w0 r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r5.getClass()
            boolean r0 = r8 instanceof com.quizlet.data.repository.metering.h
            if (r0 == 0) goto L16
            r0 = r8
            com.quizlet.data.repository.metering.h r0 = (com.quizlet.data.repository.metering.h) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.data.repository.metering.h r0 = new com.quizlet.data.repository.metering.h
            r0.<init>(r5, r8)
        L1b:
            java.lang.Object r8 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3f
            if (r2 == r4) goto L39
            if (r2 != r3) goto L31
            com.quizlet.data.repository.metering.j r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L2f
            goto L6d
        L2f:
            r6 = move-exception
            goto L70
        L31:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L39:
            com.quizlet.data.repository.metering.j r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Exception -> L2f
            goto L5b
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.data.model.w0 r7 = d(r6, r7)     // Catch: java.lang.Exception -> L2f
            boolean r6 = r7.equals(r6)     // Catch: java.lang.Exception -> L2f
            if (r6 == 0) goto L5e
            java.lang.Object r6 = r5.a     // Catch: java.lang.Exception -> L2f
            com.quizlet.data.repository.folderwithcreator.e r6 = (com.quizlet.data.repository.folderwithcreator.e) r6     // Catch: java.lang.Exception -> L2f
            r0.j = r5     // Catch: java.lang.Exception -> L2f
            r0.m = r4     // Catch: java.lang.Exception -> L2f
            java.lang.Object r8 = r6.s(r7, r0)     // Catch: java.lang.Exception -> L2f
            if (r8 != r1) goto L5b
            goto L6c
        L5b:
            com.quizlet.data.model.w0 r8 = (com.quizlet.data.model.InterfaceC4176w0) r8     // Catch: java.lang.Exception -> L2f
            goto L79
        L5e:
            java.lang.Object r6 = r5.b     // Catch: java.lang.Exception -> L2f
            com.quizlet.data.repository.folderset.c r6 = (com.quizlet.data.repository.folderset.c) r6     // Catch: java.lang.Exception -> L2f
            r0.j = r5     // Catch: java.lang.Exception -> L2f
            r0.m = r3     // Catch: java.lang.Exception -> L2f
            java.lang.Object r8 = r6.z(r7, r0)     // Catch: java.lang.Exception -> L2f
            if (r8 != r1) goto L6d
        L6c:
            return r1
        L6d:
            com.quizlet.data.model.w0 r8 = (com.quizlet.data.model.InterfaceC4176w0) r8     // Catch: java.lang.Exception -> L2f
            goto L79
        L70:
            java.lang.Object r5 = r5.c
            org.slf4j.b r5 = (org.slf4j.b) r5
            java.lang.String r7 = "Error while syncing MeteringInfo"
            r5.h(r7, r6)
        L79:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.metering.j.c(com.quizlet.data.repository.metering.j, com.quizlet.data.model.w0, com.quizlet.data.model.w0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v3, types: [com.quizlet.data.model.x0[], java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r0v9 */
    public static InterfaceC4176w0 d(InterfaceC4176w0 interfaceC4176w0, InterfaceC4176w0 interfaceC4176w02) throws MeteringInfoCombinedRepository$MeteringInfoNotFound {
        InterfaceC4176w0 interfaceC4176w03;
        if (interfaceC4176w02 != null) {
            if (interfaceC4176w0 != null && (interfaceC4176w02 instanceof C4179x0) && (interfaceC4176w0 instanceof C4179x0)) {
                Iterator it2 = B.j(new C4179x0[]{interfaceC4176w02, interfaceC4176w0}).iterator();
                if (it2.hasNext()) {
                    ?? next = it2.next();
                    if (it2.hasNext()) {
                        int i = ((C4179x0) next).a;
                        do {
                            Object next2 = it2.next();
                            int i2 = ((C4179x0) next2).a;
                            next = next;
                            if (i < i2) {
                                next = next2;
                                i = i2;
                            }
                        } while (it2.hasNext());
                    }
                    interfaceC4176w03 = next;
                } else {
                    interfaceC4176w03 = null;
                }
                interfaceC4176w0 = (C4179x0) interfaceC4176w03;
                if (interfaceC4176w0 == null) {
                    interfaceC4176w02 = (C4179x0) interfaceC4176w02;
                    interfaceC4176w0 = interfaceC4176w02;
                }
            } else {
                interfaceC4176w0 = interfaceC4176w02;
            }
        }
        if (interfaceC4176w0 != null) {
            return interfaceC4176w0;
        }
        throw new MeteringInfoCombinedRepository$MeteringInfoNotFound("Unable to fetch MeteringInfo from storage or network");
    }

    @Override // com.quizlet.data.repository.metering.a
    public Object a(long j, Long l, P p, kotlin.coroutines.jvm.internal.c cVar) {
        return E.J((AbstractC5040y) this.d, new f(this, j, l, p, null), cVar);
    }

    public w0 e(C4950i modelClass, String key) {
        w0 viewModel;
        w0 w0VarA;
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(key, "key");
        synchronized (((androidx.lifecycle.viewmodel.internal.c) this.d)) {
            try {
                B0 b0 = (B0) this.a;
                b0.getClass();
                Intrinsics.checkNotNullParameter(key, "key");
                viewModel = (w0) b0.a.get(key);
                if (modelClass.g(viewModel)) {
                    y0 y0Var = (y0) this.b;
                    if (y0Var instanceof s0) {
                        s0 s0Var = (s0) y0Var;
                        Intrinsics.d(viewModel);
                        s0Var.getClass();
                        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
                        C c = s0Var.d;
                        if (c != null) {
                            androidx.savedstate.d dVar = s0Var.e;
                            Intrinsics.d(dVar);
                            p0.a(viewModel, dVar, c);
                        }
                    }
                    Intrinsics.e(viewModel, "null cannot be cast to non-null type T of androidx.lifecycle.viewmodel.ViewModelProviderImpl.getViewModel");
                } else {
                    androidx.lifecycle.viewmodel.e extras = new androidx.lifecycle.viewmodel.e((androidx.lifecycle.viewmodel.c) this.c);
                    extras.b(A0.b, key);
                    y0 factory = (y0) this.b;
                    Intrinsics.checkNotNullParameter(factory, "factory");
                    Intrinsics.checkNotNullParameter(modelClass, "modelClass");
                    Intrinsics.checkNotNullParameter(extras, "extras");
                    try {
                        try {
                            w0VarA = factory.c(modelClass, extras);
                        } catch (AbstractMethodError unused) {
                            w0VarA = factory.b(kotlin.jvm.a.b(modelClass), extras);
                        }
                    } catch (AbstractMethodError unused2) {
                        w0VarA = factory.a(kotlin.jvm.a.b(modelClass));
                    }
                    viewModel = w0VarA;
                    B0 b02 = (B0) this.a;
                    b02.getClass();
                    Intrinsics.checkNotNullParameter(key, "key");
                    Intrinsics.checkNotNullParameter(viewModel, "viewModel");
                    w0 w0Var = (w0) b02.a.put(key, viewModel);
                    if (w0Var != null) {
                        w0Var.x();
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return viewModel;
    }

    public void f() {
        this.b = 12;
    }

    public void g(int i) throws InvalidAlgorithmParameterException {
        if (i != 16 && i != 24 && i != 32) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 16-byte, 24-byte and 32-byte AES keys are supported", Integer.valueOf(i)));
        }
        this.a = Integer.valueOf(i);
    }

    public void h() {
        this.c = 16;
    }

    public Pw i() throws GeneralSecurityException {
        Integer num = (Integer) this.a;
        if (num == null) {
            throw new GeneralSecurityException("Key size is not set");
        }
        if (((Integer) this.b) == null) {
            throw new GeneralSecurityException("IV size is not set");
        }
        if (((Integer) this.c) == null) {
            throw new GeneralSecurityException("Tag size is not set");
        }
        int iIntValue = num.intValue();
        ((Integer) this.b).getClass();
        ((Integer) this.c).getClass();
        return new Pw(iIntValue, (C2332lw) this.d);
    }

    @Override // com.google.android.gms.internal.ads.Ai
    public void k(boolean z, Context context, C2058fh c2058fh) throws zzdgh {
        boolean zU;
        try {
            int iOrdinal = ((com.google.android.gms.ads.c) this.c).ordinal();
            InterfaceC1965db interfaceC1965db = (InterfaceC1965db) this.b;
            if (iOrdinal == 1) {
                zU = interfaceC1965db.U(new com.google.android.gms.dynamic.b(context));
            } else {
                if (iOrdinal != 2) {
                    if (iOrdinal == 5) {
                        zU = interfaceC1965db.W(new com.google.android.gms.dynamic.b(context));
                    }
                    throw new zzdgh("Adapter failed to show.");
                }
                zU = interfaceC1965db.B3(new com.google.android.gms.dynamic.b(context));
            }
            if (zU) {
                C2146hh c2146hh = (C2146hh) this.d;
                if (c2146hh == null) {
                    return;
                }
                if (((Boolean) r.d.c.a(AbstractC2773w7.z1)).booleanValue() || ((Vp) this.a).Y != 2) {
                    return;
                }
                c2146hh.a();
                return;
            }
            throw new zzdgh("Adapter failed to show.");
        } catch (Throwable th) {
            throw new zzdgh(th);
        }
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onFailure(OTResponse oTResponse) {
        com.onetrust.otpublishers.headless.Internal.Network.d dVar = (com.onetrust.otpublishers.headless.Internal.Network.d) this.b;
        StringBuilder sb = new StringBuilder("IAB Vendor list Api called ");
        String str = (String) this.c;
        sb.append(str);
        OTLogger.c("NetworkRequestHandler", 3, sb.toString());
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(8);
        aVar.c("https://geolocation.1trust.app/");
        aVar.b(new C5177b(2));
        aVar.a = new A(new z());
        ((com.onetrust.otpublishers.headless.Internal.Network.a) aVar.e().b(com.onetrust.otpublishers.headless.Internal.Network.a.class)).a(str).j(new com.quizlet.data.repository.set.f(dVar, (OTCallback) this.a, (OTResponse) this.d));
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onSuccess(OTResponse oTResponse) {
        OTCallback oTCallback = (OTCallback) this.a;
        if (oTCallback != null) {
            oTCallback.onSuccess(oTResponse);
        }
    }

    @Override // com.google.android.gms.internal.ads.Ai
    /* renamed from: zza */
    public Vp mo17zza() {
        return (Vp) this.a;
    }

    public j(Vp vp, InterfaceC1965db interfaceC1965db, com.google.android.gms.ads.c cVar) {
        this.d = null;
        this.a = vp;
        this.b = interfaceC1965db;
        this.c = cVar;
    }

    public j(OTCallback oTCallback, com.onetrust.otpublishers.headless.Internal.Network.d dVar, String str, OTResponse oTResponse) {
        this.a = oTCallback;
        this.b = dVar;
        this.c = str;
        this.d = oTResponse;
    }

    public j(B0 store, y0 factory, androidx.lifecycle.viewmodel.c defaultExtras) {
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultExtras, "defaultExtras");
        this.a = store;
        this.b = factory;
        this.c = defaultExtras;
        this.d = new androidx.lifecycle.viewmodel.internal.c();
    }
}
