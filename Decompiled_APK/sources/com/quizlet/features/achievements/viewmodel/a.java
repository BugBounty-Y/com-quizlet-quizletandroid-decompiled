package com.quizlet.features.achievements.viewmodel;

import com.quizlet.data.model.C4166t;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public com.quizlet.data.interactor.achievements.i j;
    public com.quizlet.data.interactor.achievements.a k;
    public s0 l;
    public b m;
    public Object n;
    public kotlinx.collections.immutable.b o;
    public kotlinx.collections.immutable.b p;
    public kotlinx.collections.immutable.b q;
    public kotlinx.collections.immutable.b r;
    public kotlinx.collections.immutable.b s;
    public kotlinx.collections.immutable.b t;
    public C4166t u;
    public int v;
    public final /* synthetic */ b w;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, h hVar) {
        super(2, hVar);
        this.w = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.w, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0092, code lost:
    
        if (r3 == r2) goto L17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x032f, code lost:
    
        r35 = true;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Path cross not found for [B:73:0x02ea, B:74:0x02f1], limit reached: 150 */
    /* JADX WARN: Removed duplicated region for block: B:110:0x0399  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x03a8  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x03b9  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x040a  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x040f  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0414  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x0428  */
    /* JADX WARN: Removed duplicated region for block: B:132:0x045d  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00bd A[LOOP:0: B:29:0x00b7->B:31:0x00bd, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00e6 A[LOOP:1: B:33:0x00e0->B:35:0x00e6, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x010f A[LOOP:2: B:37:0x0109->B:39:0x010f, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0138 A[LOOP:3: B:41:0x0132->B:43:0x0138, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:47:0x0161 A[LOOP:4: B:45:0x015b->B:47:0x0161, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:51:0x018a A[LOOP:5: B:49:0x0184->B:51:0x018a, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x01a5  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x01e5  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x029f A[LOOP:7: B:66:0x0299->B:68:0x029f, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x02cd A[LOOP:8: B:71:0x02cd->B:107:0x0383, LOOP_START, PHI: r6 r12 r13
  0x02cd: PHI (r6v12 java.util.List) = (r6v32 java.util.List), (r6v22 java.util.List) binds: [B:70:0x02cb, B:107:0x0383] A[DONT_GENERATE, DONT_INLINE]
  0x02cd: PHI (r12v8 java.time.LocalDate) = (r12v4 java.time.LocalDate), (r12v16 java.time.LocalDate) binds: [B:70:0x02cb, B:107:0x0383] A[DONT_GENERATE, DONT_INLINE]
  0x02cd: PHI (r13v15 long) = (r13v10 long), (r13v22 long) binds: [B:70:0x02cb, B:107:0x0383] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r1v10, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v11, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v13, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v15, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v9, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v13, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v24, types: [kotlin.collections.K] */
    /* JADX WARN: Type inference failed for: r6v25, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [java.lang.Object] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:117:0x03f1 -> B:118:0x0404). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:127:0x0428 -> B:126:0x0425). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r43) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1121
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.achievements.viewmodel.a.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
