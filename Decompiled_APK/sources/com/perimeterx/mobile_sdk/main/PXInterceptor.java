package com.perimeterx.mobile_sdk.main;

import androidx.annotation.Keep;
import kotlin.Metadata;
import okhttp3.u;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PXInterceptor implements u {
    /* JADX WARN: Removed duplicated region for block: B:22:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x002f  */
    @Override // okhttp3.u
    @org.jetbrains.annotations.NotNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public okhttp3.H intercept(@org.jetbrains.annotations.NotNull okhttp3.t r10) throws java.lang.Throwable {
        /*
            r9 = this;
            java.lang.String r0 = "chain"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r0)
            com.perimeterx.mobile_sdk.session.l r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.L4.a
            r1 = 0
            java.lang.String r2 = "url"
            if (r0 == 0) goto L2f
            r0 = r10
            okhttp3.internal.http.f r0 = (okhttp3.internal.http.f) r0
            okhttp3.C r0 = r0.e
            okhttp3.s r0 = r0.a
            java.net.URL r0 = r0.k()
            com.perimeterx.mobile_sdk.business_logic.b r3 = com.perimeterx.mobile_sdk.business_logic.b.a
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            java.lang.String r4 = "source"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r4)
            com.perimeterx.mobile_sdk.session.d r4 = com.perimeterx.mobile_sdk.session.l.b(r0, r3)
            if (r4 == 0) goto L2f
            boolean r0 = r4.h(r0, r3)
            goto L30
        L2f:
            r0 = r1
        L30:
            if (r0 != 0) goto L3b
            okhttp3.internal.http.f r10 = (okhttp3.internal.http.f) r10
            okhttp3.C r0 = r10.e
            okhttp3.H r10 = r10.b(r0)
            return r10
        L3b:
            r0 = r10
            okhttp3.internal.http.f r0 = (okhttp3.internal.http.f) r0
            okhttp3.C r0 = r0.e
            kotlinx.coroutines.scheduling.e r3 = kotlinx.coroutines.O.a
            kotlinx.coroutines.internal.d r3 = kotlinx.coroutines.E.c(r3)
            com.perimeterx.mobile_sdk.detections.device.motion_interception.d r4 = new com.perimeterx.mobile_sdk.detections.device.motion_interception.d
            r5 = 0
            r6 = 2
            r4.<init>(r0, r5, r6)
            r6 = 3
            kotlinx.coroutines.E.A(r3, r5, r5, r4, r6)
            kotlin.Pair r3 = com.google.android.gms.internal.mlkit_vision_document_scanner.L4.d(r0, r10)
            java.lang.Object r4 = r3.a
            okhttp3.H r4 = (okhttp3.H) r4
            java.lang.Object r3 = r3.b
            java.lang.String r3 = (java.lang.String) r3
            com.perimeterx.mobile_sdk.session.l r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.L4.a
            if (r5 == 0) goto Lb1
            okhttp3.s r5 = r0.a
            java.net.URL r5 = r5.k()
            java.lang.String r3 = java.lang.String.valueOf(r3)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
            java.lang.String r6 = "originalRequestResponse"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r6)
            com.perimeterx.mobile_sdk.business_logic.b r7 = com.perimeterx.mobile_sdk.business_logic.b.a
            com.perimeterx.mobile_sdk.session.d r7 = com.perimeterx.mobile_sdk.session.l.b(r5, r7)
            r8 = 1
            if (r7 == 0) goto Lad
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r2)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r6)
            com.google.mlkit.common.sdkinternal.model.a r2 = r7.g
            r2.getClass()
            com.perimeterx.mobile_sdk.session.m r2 = r7.b
            java.lang.String r5 = "session"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r2, r5)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r6)
            com.perimeterx.mobile_sdk.main.PXPolicy r5 = r2.b
            com.perimeterx.mobile_sdk.main.PXPolicyUrlRequestInterceptionType r5 = r5.getUrlRequestInterceptionType()
            com.perimeterx.mobile_sdk.main.PXPolicyUrlRequestInterceptionType r6 = com.perimeterx.mobile_sdk.main.PXPolicyUrlRequestInterceptionType.INTERCEPT_AND_RETRY_REQUEST
            if (r5 != r6) goto Lad
            com.perimeterx.mobile_sdk.PerimeterX r5 = com.perimeterx.mobile_sdk.PerimeterX.INSTANCE
            boolean r3 = r5.isChallengeSolvedError(r3)
            if (r3 == 0) goto Lad
            com.perimeterx.mobile_sdk.main.PXPolicy r2 = r2.b
            boolean r2 = r2.getDoctorCheckEnabled()
            if (r2 != 0) goto Lad
            r2 = r8
            goto Lae
        Lad:
            r2 = r1
        Lae:
            if (r2 != r8) goto Lb1
            r1 = r8
        Lb1:
            if (r1 == 0) goto Lbc
            kotlin.Pair r10 = com.google.android.gms.internal.mlkit_vision_document_scanner.L4.d(r0, r10)
            java.lang.Object r10 = r10.a
            okhttp3.H r10 = (okhttp3.H) r10
            return r10
        Lbc:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.perimeterx.mobile_sdk.main.PXInterceptor.intercept(okhttp3.t):okhttp3.H");
    }
}
