package com.quizlet.quizletandroid.util.file;

import com.quizlet.data.repository.set.f;
import java.io.InputStream;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public List j;
    public f k;
    public Iterator l;
    public String m;
    public InputStream n;
    public byte[] o;
    public int p;
    public int q;
    public int r;
    public final /* synthetic */ List s;
    public final /* synthetic */ f t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(List list, f fVar, h hVar) {
        super(2, hVar);
        this.s = list;
        this.t = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.s, this.t, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Path cross not found for [B:24:0x00b0, B:26:0x00b6], limit reached: 42 */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00d2  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00ec A[RETURN] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:18:0x0066 -> B:32:0x00df). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:20:0x00a7 -> B:22:0x00aa). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r14) throws java.io.FileNotFoundException {
        /*
            Method dump skipped, instructions count: 237
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.util.file.e.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
