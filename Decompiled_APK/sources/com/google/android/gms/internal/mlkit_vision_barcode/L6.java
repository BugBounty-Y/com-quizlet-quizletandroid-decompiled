package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class L6 {
    /* JADX WARN: Removed duplicated region for block: B:27:0x006b  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:33:0x0082 -> B:25:0x0065). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:34:0x0085 -> B:25:0x0065). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(java.util.List r6, androidx.datastore.core.C1079k r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            boolean r0 = r8 instanceof androidx.datastore.core.C1073e
            if (r0 == 0) goto L13
            r0 = r8
            androidx.datastore.core.e r0 = (androidx.datastore.core.C1073e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.datastore.core.e r0 = new androidx.datastore.core.e
            r0.<init>(r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L42
            if (r2 == r4) goto L3a
            if (r2 != r3) goto L32
            java.util.Iterator r6 = r0.k
            java.io.Serializable r7 = r0.j
            kotlin.jvm.internal.J r7 = (kotlin.jvm.internal.J) r7
            androidx.glance.appwidget.protobuf.Z.e(r8)     // Catch: java.lang.Throwable -> L30
            goto L65
        L30:
            r8 = move-exception
            goto L7e
        L32:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L3a:
            java.io.Serializable r6 = r0.j
            java.util.List r6 = (java.util.List) r6
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L5c
        L42:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            java.util.ArrayList r8 = new java.util.ArrayList
            r8.<init>()
            androidx.datastore.core.g r2 = new androidx.datastore.core.g
            r5 = 0
            r2.<init>(r6, r8, r5)
            r0.j = r8
            r0.m = r4
            java.lang.Object r6 = r7.a(r2, r0)
            if (r6 != r1) goto L5b
            goto L93
        L5b:
            r6 = r8
        L5c:
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            java.util.Iterator r6 = r6.iterator()
        L65:
            boolean r8 = r6.hasNext()
            if (r8 == 0) goto L8b
            java.lang.Object r8 = r6.next()
            kotlin.jvm.functions.Function1 r8 = (kotlin.jvm.functions.Function1) r8
            r0.j = r7     // Catch: java.lang.Throwable -> L30
            r0.k = r6     // Catch: java.lang.Throwable -> L30
            r0.m = r3     // Catch: java.lang.Throwable -> L30
            java.lang.Object r8 = r8.invoke(r0)     // Catch: java.lang.Throwable -> L30
            if (r8 != r1) goto L65
            goto L93
        L7e:
            java.lang.Object r2 = r7.a
            if (r2 != 0) goto L85
            r7.a = r8
            goto L65
        L85:
            java.lang.Throwable r2 = (java.lang.Throwable) r2
            kotlin.C4937f.a(r2, r8)
            goto L65
        L8b:
            java.lang.Object r6 = r7.a
            java.lang.Throwable r6 = (java.lang.Throwable) r6
            if (r6 != 0) goto L94
            kotlin.Unit r1 = kotlin.Unit.a
        L93:
            return r1
        L94:
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.L6.a(java.util.List, androidx.datastore.core.k, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object b(Context context, Class entryPoint) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(entryPoint, "entryPoint");
        return K6.b(entryPoint, N6.b(context.getApplicationContext()));
    }

    public static final com.quizlet.sharedconfig.study_setting_metadata.b c(assistantMode.enums.k kVar) {
        Intrinsics.checkNotNullParameter(kVar, "<this>");
        int iOrdinal = kVar.ordinal();
        if (iOrdinal == 10) {
            return com.quizlet.sharedconfig.study_setting_metadata.b.FILL_IN_THE_BLANK;
        }
        switch (iOrdinal) {
            case 0:
                return com.quizlet.sharedconfig.study_setting_metadata.b.WRITTEN;
            case 1:
                return com.quizlet.sharedconfig.study_setting_metadata.b.MATCHING;
            case 2:
                return com.quizlet.sharedconfig.study_setting_metadata.b.MULTIPLE_CHOICE;
            case 3:
                return com.quizlet.sharedconfig.study_setting_metadata.b.TRUE_FALSE;
            case 4:
                return com.quizlet.sharedconfig.study_setting_metadata.b.REVEAL_SELF_ASSESSMENT;
            case 5:
                return com.quizlet.sharedconfig.study_setting_metadata.b.MULTIPLE_CHOICE_WITH_NONE_OPTION;
            case 6:
                return com.quizlet.sharedconfig.study_setting_metadata.b.COPY_ANSWER;
            default:
                throw new IllegalStateException("Can't map QuestionType to AssistantModeQuestionType: [" + kVar + "]");
        }
    }
}
