package com.quizlet.data.repository.studysetwithcreator;

import android.content.Context;
import androidx.paging.C1352z;
import androidx.paging.i1;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC1955d8;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Am;
import com.google.android.gms.internal.ads.C1849aq;
import com.google.android.gms.internal.ads.C2267ka;
import com.google.android.gms.internal.ads.C2752vn;
import com.google.android.gms.internal.ads.C2880ym;
import com.google.android.gms.internal.ads.Cy;
import com.google.android.gms.internal.ads.Dy;
import com.google.android.gms.internal.ads.Ey;
import com.google.android.gms.internal.ads.Hq;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Vp;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.quizlet.quizletandroid.R;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements Hq, OTCallback {
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public d(int i) {
        switch (i) {
            case 4:
                this.a = null;
                this.b = null;
                this.c = null;
                this.d = Dy.e;
                break;
            default:
                this.a = new Object();
                this.b = new Object();
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(java.lang.String r12, java.lang.String r13, java.lang.Integer r14, int r15, com.quizlet.data.model.C4186z1 r16, kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            r11 = this;
            r0 = r17
            boolean r2 = r0 instanceof com.quizlet.data.repository.studysetwithcreator.a
            if (r2 == 0) goto L16
            r2 = r0
            com.quizlet.data.repository.studysetwithcreator.a r2 = (com.quizlet.data.repository.studysetwithcreator.a) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L16
            int r3 = r3 - r4
            r2.l = r3
        L14:
            r8 = r2
            goto L1c
        L16:
            com.quizlet.data.repository.studysetwithcreator.a r2 = new com.quizlet.data.repository.studysetwithcreator.a
            r2.<init>(r11, r0)
            goto L14
        L1c:
            java.lang.Object r0 = r8.j
            kotlin.coroutines.intrinsics.a r9 = kotlin.coroutines.intrinsics.a.a
            int r2 = r8.l
            r10 = 1
            if (r2 == 0) goto L33
            if (r2 != r10) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L50
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.repository.studysetwithcreator.b r0 = new com.quizlet.data.repository.studysetwithcreator.b
            r7 = 0
            r1 = r11
            r2 = r12
            r3 = r13
            r4 = r14
            r5 = r15
            r6 = r16
            r0.<init>(r1, r2, r3, r4, r5, r6, r7)
            r8.l = r10
            java.lang.Object r2 = r11.c
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r8)
            if (r0 != r9) goto L50
            return r9
        L50:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.studysetwithcreator.d.a(java.lang.String, java.lang.String, java.lang.Integer, int, com.quizlet.data.model.z1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(com.quizlet.studiablemodels.grading.d r18, int r19, boolean r20, boolean r21, kotlin.coroutines.jvm.internal.c r22) {
        /*
            Method dump skipped, instructions count: 414
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.studysetwithcreator.d.b(com.quizlet.studiablemodels.grading.d, int, boolean, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void c(i1 i1Var, Function2 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        ReentrantLock reentrantLock = (ReentrantLock) this.d;
        try {
            reentrantLock.lock();
            if (i1Var != null) {
                this.c = i1Var;
            }
            block.invoke((C1352z) this.a, (C1352z) this.b);
            Unit unit = Unit.a;
            reentrantLock.unlock();
        } catch (Throwable th) {
            reentrantLock.unlock();
            throw th;
        }
    }

    public C2267ka d(Context context, VersionInfoParcel versionInfoParcel, Uq uq) {
        C2267ka c2267ka;
        String str;
        synchronized (this.a) {
            try {
                if (((C2267ka) this.c) == null) {
                    if (((Boolean) AbstractC1955d8.f.o()).booleanValue()) {
                        str = (String) r.d.c.a(AbstractC2773w7.a);
                    } else {
                        str = (String) r.d.c.a(AbstractC2773w7.b);
                    }
                    Context applicationContext = context.getApplicationContext();
                    if (applicationContext != null) {
                        context = applicationContext;
                    }
                    this.c = new C2267ka(context, versionInfoParcel, str, uq);
                }
                c2267ka = (C2267ka) this.c;
            } catch (Throwable th) {
                throw th;
            }
        }
        return c2267ka;
    }

    public C2267ka e(Context context, VersionInfoParcel versionInfoParcel, Uq uq) {
        C2267ka c2267ka;
        synchronized (this.b) {
            try {
                if (((C2267ka) this.d) == null) {
                    Context applicationContext = context.getApplicationContext();
                    if (applicationContext != null) {
                        context = applicationContext;
                    }
                    this.d = new C2267ka(context, versionInfoParcel, (String) LA.k.o(), uq);
                }
                c2267ka = (C2267ka) this.d;
            } catch (Throwable th) {
                throw th;
            }
        }
        return c2267ka;
    }

    public void f(int i) {
        this.a = Integer.valueOf(i);
    }

    public void g(int i) {
        this.b = Integer.valueOf(i);
    }

    public Ey h() {
        Integer num = (Integer) this.a;
        if (num == null) {
            throw new GeneralSecurityException("key size is not set");
        }
        if (((Integer) this.b) == null) {
            throw new GeneralSecurityException("tag size is not set");
        }
        if (((Cy) this.c) == null) {
            throw new GeneralSecurityException("hash type is not set");
        }
        if (num.intValue() < 16) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size in bytes %d; must be at least 16 bytes", (Integer) this.a));
        }
        Integer num2 = (Integer) this.b;
        int iIntValue = num2.intValue();
        Cy cy = (Cy) this.c;
        if (iIntValue < 10) {
            throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; must be at least 10 bytes", num2));
        }
        if (cy == Cy.b) {
            if (iIntValue > 20) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 20 bytes for SHA1", num2));
            }
        } else if (cy == Cy.c) {
            if (iIntValue > 28) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 28 bytes for SHA224", num2));
            }
        } else if (cy == Cy.d) {
            if (iIntValue > 32) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 32 bytes for SHA256", num2));
            }
        } else if (cy == Cy.e) {
            if (iIntValue > 48) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 48 bytes for SHA384", num2));
            }
        } else {
            if (cy != Cy.f) {
                throw new GeneralSecurityException("unknown hash type; must be SHA256, SHA384 or SHA512");
            }
            if (iIntValue > 64) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 64 bytes for SHA512", num2));
            }
        }
        return new Ey(((Integer) this.a).intValue(), ((Integer) this.b).intValue(), (Dy) this.d, (Cy) this.c);
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onFailure(OTResponse oTResponse) {
        com.onetrust.otpublishers.headless.Internal.profile.c cVar = (com.onetrust.otpublishers.headless.Internal.profile.c) this.d;
        cVar.getClass();
        OTLogger.c("MultiprofileConsent", 3, "Switch profile with data download failed, so switching profile without data download now.");
        cVar.c((String) this.b, (OTPublishersHeadlessSDK) this.c);
        OTCallback oTCallback = (OTCallback) this.a;
        if (oTCallback != null) {
            oTCallback.onSuccess(new OTResponse(OTResponseType.OT_SUCCESS, 9, cVar.c.getResources().getString(R.string.ott_data_parsed_with_existing_data), ""));
        }
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onSuccess(OTResponse oTResponse) {
        OTLogger.c("MultiprofileConsent", 3, "Switch profile with data download successful, returning app callback.");
        OTCallback oTCallback = (OTCallback) this.a;
        if (oTCallback != null) {
            oTCallback.onSuccess(oTResponse);
        }
    }

    @Override // com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        ((Am) ((C2752vn) this.a).e).a((C1849aq) this.b, (Vp) this.c, (C2880ym) this.d);
    }

    public d(com.quizlet.features.questiontypes.basequestion.c answerLabelUseCase) {
        Intrinsics.checkNotNullParameter(answerLabelUseCase, "answerLabelUseCase");
    }
}
