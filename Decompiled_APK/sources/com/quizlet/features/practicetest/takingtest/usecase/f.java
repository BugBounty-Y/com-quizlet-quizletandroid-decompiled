package com.quizlet.features.practicetest.takingtest.usecase;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.firebase.messaging.p;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.data.model.C4112b1;
import com.quizlet.data.model.R0;
import com.quizlet.data.model.X0;
import com.quizlet.features.practicetest.common.data.i;
import com.quizlet.features.practicetest.common.data.j;
import com.quizlet.features.practicetest.common.data.l;
import com.quizlet.features.practicetest.takingtest.data.C4407a;
import com.quizlet.features.practicetest.takingtest.data.C4408b;
import com.quizlet.features.practicetest.takingtest.data.C4409c;
import com.quizlet.features.practicetest.takingtest.data.C4411e;
import com.quizlet.features.practicetest.takingtest.data.C4412f;
import com.quizlet.features.practicetest.takingtest.data.F;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4410d;
import com.quizlet.features.practicetest.takingtest.data.InterfaceC4415i;
import com.quizlet.features.practicetest.takingtest.data.M;
import com.quizlet.features.practicetest.takingtest.data.N;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final com.quizlet.data.interactor.achievements.f a;
    public final com.quizlet.data.interactor.course.a b;
    public final p c;
    public final com.google.firebase.crashlytics.internal.settings.b d;
    public final SimpleDateFormat e;
    public int f;
    public ArrayList g;
    public InterfaceC4415i[] h;
    public final LinkedHashSet i;
    public Long j;
    public final l k;

    public f(com.quizlet.data.interactor.achievements.f getPracticeTestQuestionsUseCase, com.quizlet.data.interactor.course.a createPracticeTestUseCase, p gradePracticeTestUseCase, com.google.firebase.crashlytics.internal.settings.b getPracticeTestDetailUseCase, com.google.firebase.heartbeatinfo.e getDefaultPracticeTestConfigurationUseCase) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(getPracticeTestQuestionsUseCase, "getPracticeTestQuestionsUseCase");
        Intrinsics.checkNotNullParameter(createPracticeTestUseCase, "createPracticeTestUseCase");
        Intrinsics.checkNotNullParameter(gradePracticeTestUseCase, "gradePracticeTestUseCase");
        Intrinsics.checkNotNullParameter(getPracticeTestDetailUseCase, "getPracticeTestDetailUseCase");
        Intrinsics.checkNotNullParameter(getDefaultPracticeTestConfigurationUseCase, "getDefaultPracticeTestConfigurationUseCase");
        this.a = getPracticeTestQuestionsUseCase;
        this.b = createPracticeTestUseCase;
        this.c = gradePracticeTestUseCase;
        this.d = getPracticeTestDetailUseCase;
        this.e = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.getDefault());
        this.i = new LinkedHashSet();
        this.k = new l();
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(java.lang.String r11, int r12, java.util.ArrayList r13, kotlin.coroutines.jvm.internal.c r14) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.features.practicetest.takingtest.usecase.b
            if (r0 == 0) goto L14
            r0 = r14
            com.quizlet.features.practicetest.takingtest.usecase.b r0 = (com.quizlet.features.practicetest.takingtest.usecase.b) r0
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
            com.quizlet.features.practicetest.takingtest.usecase.b r0 = new com.quizlet.features.practicetest.takingtest.usecase.b
            r0.<init>(r10, r14)
            goto L12
        L1a:
            java.lang.Object r14 = r8.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.m
            r9 = 2
            r2 = 1
            if (r1 == 0) goto L40
            if (r1 == r2) goto L38
            if (r1 != r9) goto L30
            java.lang.Object r11 = r8.j
            java.lang.String r11 = (java.lang.String) r11
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L67
        L30:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L38:
            java.lang.Object r11 = r8.j
            com.quizlet.features.practicetest.takingtest.usecase.f r11 = (com.quizlet.features.practicetest.takingtest.usecase.f) r11
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L58
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.generated.enums.q0 r4 = com.quizlet.generated.enums.EnumC4513q0.TEST_SETUP_MODAL
            r8.j = r10
            r8.m = r2
            com.quizlet.data.interactor.course.a r1 = r10.b
            r3 = 1
            r5 = 0
            r2 = r11
            r6 = r12
            r7 = r13
            java.lang.Object r14 = r1.g(r2, r3, r4, r5, r6, r7, r8)
            if (r14 != r0) goto L57
            goto L65
        L57:
            r11 = r10
        L58:
            r12 = r14
            java.lang.String r12 = (java.lang.String) r12
            r8.j = r12
            r8.m = r9
            java.lang.Object r14 = r11.b(r12, r8)
            if (r14 != r0) goto L66
        L65:
            return r0
        L66:
            r11 = r12
        L67:
            com.quizlet.features.practicetest.takingtest.data.L r14 = (com.quizlet.features.practicetest.takingtest.data.L) r14
            com.quizlet.features.practicetest.takingtest.data.K r12 = new com.quizlet.features.practicetest.takingtest.data.K
            com.quizlet.features.practicetest.takingtest.data.J r13 = r14.b
            com.quizlet.features.practicetest.takingtest.data.F r13 = (com.quizlet.features.practicetest.takingtest.data.F) r13
            r12.<init>(r11, r13)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.usecase.f.a(java.lang.String, int, java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(java.lang.String r21, kotlin.coroutines.jvm.internal.c r22) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 385
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.usecase.f.b(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(java.lang.String r18, kotlin.coroutines.jvm.internal.c r19) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 242
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.usecase.f.c(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final kotlinx.collections.immutable.e d() {
        InterfaceC4415i[] interfaceC4415iArr = this.h;
        if (interfaceC4415iArr == null) {
            Intrinsics.m("currentAnswers");
            throw null;
        }
        ArrayList arrayList = new ArrayList(interfaceC4415iArr.length);
        int length = interfaceC4415iArr.length;
        int i = 0;
        int i2 = 0;
        while (i < length) {
            InterfaceC4415i interfaceC4415i = interfaceC4415iArr[i];
            int i3 = i2 + 1;
            LinkedHashSet linkedHashSet = this.i;
            arrayList.add(new i(i2, linkedHashSet.contains(Integer.valueOf(i2)) ? j.c : linkedHashSet.contains(Integer.valueOf(i2)) ? j.c : (interfaceC4415i == null || !interfaceC4415i.a()) ? j.a : j.b));
            i++;
            i2 = i3;
        }
        return AbstractC3409x1.k(arrayList);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(java.lang.String r24, java.lang.String r25, java.lang.String r26, kotlin.coroutines.jvm.internal.c r27) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.practicetest.takingtest.usecase.f.e(java.lang.String, java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final F f() {
        int i = this.f;
        ArrayList arrayList = this.g;
        if (arrayList == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        if (i < B.i(arrayList)) {
            this.f++;
        }
        int i2 = this.f;
        ArrayList arrayList2 = this.g;
        if (arrayList2 == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        int size = arrayList2.size();
        ArrayList arrayList3 = this.g;
        if (arrayList3 == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        C4412f c4412f = (C4412f) arrayList3.get(this.f);
        kotlinx.collections.immutable.e eVarD = d();
        InterfaceC4415i[] interfaceC4415iArr = this.h;
        if (interfaceC4415iArr != null) {
            return new F(i2, size, c4412f, eVarD, (N) null, interfaceC4415iArr[this.f], (M) null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
        }
        Intrinsics.m("currentAnswers");
        throw null;
    }

    public final F g() {
        int i = this.f;
        if (i > 0) {
            this.f = i - 1;
        }
        int i2 = this.f;
        ArrayList arrayList = this.g;
        if (arrayList == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        int size = arrayList.size();
        ArrayList arrayList2 = this.g;
        if (arrayList2 == null) {
            Intrinsics.m("questionsList");
            throw null;
        }
        C4412f c4412f = (C4412f) arrayList2.get(this.f);
        kotlinx.collections.immutable.e eVarD = d();
        InterfaceC4415i[] interfaceC4415iArr = this.h;
        if (interfaceC4415iArr != null) {
            return new F(i2, size, c4412f, eVarD, (N) null, interfaceC4415iArr[this.f], (M) null, OTUIDisplayReasonCode.UIShownCode.PC_SHOWN_BACKWARD_COMPATIBILITY);
        }
        Intrinsics.m("currentAnswers");
        throw null;
    }

    /* JADX WARN: Type inference failed for: r5v6, types: [java.lang.Iterable, java.lang.Object] */
    public final C4412f h(X0 x0, int i) {
        InterfaceC4410d c4408b;
        ArrayList arrayList;
        String str = x0.a;
        List<C4112b1> list = x0.d;
        ArrayList arrayList2 = null;
        if (list.isEmpty()) {
            c4408b = C4409c.a;
        } else {
            ArrayList arrayList3 = new ArrayList(C.q(list, 10));
            for (C4112b1 c4112b1 : list) {
                String str2 = c4112b1.a;
                ?? r5 = c4112b1.b;
                if (r5 != 0) {
                    arrayList = new ArrayList(C.q(r5, 10));
                    for (R0 r0 : r5) {
                        arrayList.add(new C4411e(r0.a, r0.b));
                    }
                } else {
                    arrayList = null;
                }
                arrayList3.add(new C4407a(arrayList, str2));
            }
            c4408b = new C4408b(arrayList3);
        }
        ArrayList arrayList4 = x0.f;
        if (arrayList4 != null) {
            arrayList2 = new ArrayList(C.q(arrayList4, 10));
            Iterator it2 = arrayList4.iterator();
            while (it2.hasNext()) {
                R0 r02 = (R0) it2.next();
                arrayList2.add(new C4411e(r02.a, r02.b));
            }
        }
        ArrayList arrayList5 = arrayList2;
        boolean zContains = this.i.contains(Integer.valueOf(i));
        return new C4412f(str, x0.b, x0.c, c4408b, arrayList5, x0.e, i, true, zContains);
    }
}
