package androidx.compose.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import kotlin.Unit;

/* renamed from: androidx.compose.runtime.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0830u0 extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public List j;
    public List k;
    public List l;
    public androidx.collection.J m;
    public androidx.collection.J n;
    public androidx.collection.J o;
    public Set p;
    public androidx.collection.J q;
    public int r;
    public /* synthetic */ W s;
    public final /* synthetic */ C0832v0 t;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0830u0(C0832v0 c0832v0, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.t = c0832v0;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ba  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00fd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.compose.runtime.C0832v0 r22, java.util.List r23, java.util.List r24, java.util.List r25, androidx.collection.J r26, androidx.collection.J r27, androidx.collection.J r28, androidx.collection.J r29) {
        /*
            Method dump skipped, instructions count: 267
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0830u0.a(androidx.compose.runtime.v0, java.util.List, java.util.List, java.util.List, androidx.collection.J, androidx.collection.J, androidx.collection.J, androidx.collection.J):void");
    }

    public static final void d(List list, C0832v0 c0832v0) {
        list.clear();
        synchronized (c0832v0.c) {
            try {
                ArrayList arrayList = c0832v0.k;
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    list.add((Z) arrayList.get(i));
                }
                c0832v0.k.clear();
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        C0830u0 c0830u0 = new C0830u0(this.t, (kotlin.coroutines.h) obj3);
        c0830u0.s = (W) obj2;
        c0830u0.invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0099 A[DONT_GENERATE] */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01f9  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x013a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:45:0x012d -> B:46:0x0135). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:76:0x01f9 -> B:12:0x0094). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r23) {
        /*
            Method dump skipped, instructions count: 517
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.C0830u0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
