package androidx.compose.runtime.snapshots;

import androidx.camera.camera2.internal.C0132i;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.d0;
import androidx.compose.runtime.AbstractC0805k0;
import androidx.compose.runtime.C0775b0;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes.dex */
public final class v {
    public final kotlin.jvm.internal.r a;
    public boolean c;
    public C0132i h;
    public u i;
    public final AtomicReference b = new AtomicReference(null);
    public final C0281h d = new C0281h(this, 25);
    public final C0775b0 e = new C0775b0(this, 8);
    public final androidx.compose.runtime.collection.b f = new androidx.compose.runtime.collection.b(new u[16]);
    public final Object g = new Object();
    public long j = -1;

    /* JADX WARN: Multi-variable type inference failed */
    public v(Function1 function1) {
        this.a = (kotlin.jvm.internal.r) function1;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final boolean a(v vVar) {
        boolean z;
        Set set;
        synchronized (vVar.g) {
            z = vVar.c;
        }
        if (z) {
            return false;
        }
        boolean z2 = false;
        while (true) {
            AtomicReference atomicReference = vVar.b;
            Object obj = atomicReference.get();
            Set set2 = null;
            List list = null;
            List listSubList = null;
            if (obj != null) {
                if (obj instanceof Set) {
                    set = (Set) obj;
                } else {
                    if (!(obj instanceof List)) {
                        androidx.compose.runtime.r.d("Unexpected notification");
                        throw new KotlinNothingValueException();
                    }
                    List list2 = (List) obj;
                    Set set3 = (Set) list2.get(0);
                    if (list2.size() == 2) {
                        listSubList = list2.get(1);
                    } else if (list2.size() > 2) {
                        listSubList = list2.subList(1, list2.size());
                    }
                    set = set3;
                    list = listSubList;
                }
                while (!atomicReference.compareAndSet(obj, list)) {
                    if (atomicReference.get() != obj) {
                        break;
                    }
                }
                set2 = set;
            }
            if (set2 == null) {
                return z2;
            }
            synchronized (vVar.g) {
                try {
                    androidx.compose.runtime.collection.b bVar = vVar.f;
                    Object[] objArr = bVar.a;
                    int i = bVar.c;
                    for (int i2 = 0; i2 < i; i2++) {
                        z2 = ((u) objArr[i2]).b(set2) || z2;
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    public final void b() {
        synchronized (this.g) {
            try {
                androidx.compose.runtime.collection.b bVar = this.f;
                Object[] objArr = bVar.a;
                int i = bVar.c;
                for (int i2 = 0; i2 < i; i2++) {
                    u uVar = (u) objArr[i2];
                    uVar.e.a();
                    uVar.f.a();
                    uVar.k.a();
                    uVar.l.clear();
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.lang.Object r24) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 197
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.snapshots.v.c(java.lang.Object):void");
    }

    public final void d(Object obj, Function1 function1, Function0 function0) {
        Object obj2;
        u uVar;
        synchronized (this.g) {
            androidx.compose.runtime.collection.b bVar = this.f;
            Object[] objArr = bVar.a;
            int i = bVar.c;
            int i2 = 0;
            while (true) {
                if (i2 >= i) {
                    obj2 = null;
                    break;
                }
                obj2 = objArr[i2];
                if (((u) obj2).a == function1) {
                    break;
                } else {
                    i2++;
                }
            }
            uVar = (u) obj2;
            if (uVar == null) {
                Intrinsics.e(function1, "null cannot be cast to non-null type kotlin.Function1<kotlin.Any, kotlin.Unit>");
                O.d(1, function1);
                uVar = new u(function1);
                bVar.b(uVar);
            }
        }
        u uVar2 = this.i;
        long j = this.j;
        if (j != -1 && j != androidx.compose.runtime.internal.e.c()) {
            StringBuilder sbT = d0.t(j, "Detected multithreaded access to SnapshotStateObserver: previousThreadId=", "), currentThread={id=");
            sbT.append(androidx.compose.runtime.internal.e.c());
            sbT.append(", name=");
            sbT.append(Thread.currentThread().getName());
            sbT.append("}. Note that observation on multiple threads in layout/draw is not supported. Make sure your measure/layout/draw for each Owner (AndroidComposeView) is executed on the same thread.");
            AbstractC0805k0.a(sbT.toString());
        }
        try {
            this.i = uVar;
            this.j = androidx.compose.runtime.internal.e.c();
            uVar.a(obj, this.e, function0);
        } finally {
            this.i = uVar2;
            this.j = j;
        }
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, java.util.Collection] */
    public final void e() {
        C0281h c0281h = this.d;
        com.quizlet.data.repository.classfolder.e eVar = m.a;
        m.f(C0821a.c);
        synchronized (m.b) {
            m.g = CollectionsKt.d0(m.g, c0281h);
            Unit unit = Unit.a;
        }
        this.h = new C0132i(c0281h);
    }
}
