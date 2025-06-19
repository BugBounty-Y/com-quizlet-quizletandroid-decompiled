package com.quizlet.remote.model.selectedterm;

import com.squareup.moshi.H;
import com.squareup.moshi.k;
import java.lang.reflect.Type;

/* loaded from: classes3.dex */
public final class c implements k {
    public final /* synthetic */ int a;

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    public static void b(Class cls, Type type) {
        Class<?> clsD = H.d(type);
        if (cls.isAssignableFrom(clsD)) {
            throw new IllegalArgumentException("No JsonAdapter for " + type + ", you should probably use " + cls.getSimpleName() + " instead of " + clsD.getSimpleName() + " (Moshi only supports the collection interfaces by default) or else register a custom JsonAdapter.");
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:199:0x03d9  */
    /* JADX WARN: Type inference failed for: r14v3, types: [java.lang.Object, java.lang.reflect.AccessibleObject, java.lang.reflect.AnnotatedElement, java.lang.reflect.Field] */
    /* JADX WARN: Type inference failed for: r18v3, types: [boolean] */
    /* JADX WARN: Type inference failed for: r19v0 */
    /* JADX WARN: Type inference failed for: r19v1, types: [java.util.Set] */
    /* JADX WARN: Type inference failed for: r19v2 */
    /* JADX WARN: Type inference failed for: r19v4 */
    /* JADX WARN: Type inference failed for: r19v6 */
    /* JADX WARN: Type inference failed for: r1v20, types: [java.lang.StringBuilder] */
    /* JADX WARN: Type inference failed for: r5v23 */
    /* JADX WARN: Type inference failed for: r5v4 */
    /* JADX WARN: Type inference failed for: r5v6 */
    @Override // com.squareup.moshi.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.squareup.moshi.l a(java.lang.reflect.Type r23, java.util.Set r24, com.squareup.moshi.D r25) throws java.lang.NoSuchFieldException, java.lang.NoSuchMethodException, java.lang.ClassNotFoundException, java.lang.SecurityException {
        /*
            Method dump skipped, instructions count: 1486
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.selectedterm.c.a(java.lang.reflect.Type, java.util.Set, com.squareup.moshi.D):com.squareup.moshi.l");
    }
}
