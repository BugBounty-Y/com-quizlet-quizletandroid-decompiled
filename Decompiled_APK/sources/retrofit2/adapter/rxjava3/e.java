package retrofit2.adapter.rxjava3;

import java.lang.reflect.Type;
import retrofit2.InterfaceC5181f;

/* loaded from: classes3.dex */
public final class e implements InterfaceC5181f {
    public final Type a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final boolean g;

    public e(Type type, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6) {
        this.a = type;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = z4;
        this.f = z5;
        this.g = z6;
    }

    @Override // retrofit2.InterfaceC5181f
    public final Type b() {
        return this.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0022  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0029  */
    /* JADX WARN: Type inference failed for: r3v13, types: [retrofit2.adapter.rxjava3.b] */
    /* JADX WARN: Type inference failed for: r3v3, types: [retrofit2.adapter.rxjava3.b] */
    @Override // retrofit2.InterfaceC5181f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object j(retrofit2.u r3) {
        /*
            r2 = this;
            com.jakewharton.rxbinding4.a r0 = new com.jakewharton.rxbinding4.a
            r1 = 9
            r0.<init>(r3, r1)
            boolean r3 = r2.b
            if (r3 == 0) goto L13
            retrofit2.adapter.rxjava3.b r3 = new retrofit2.adapter.rxjava3.b
            r1 = 1
            r3.<init>(r0, r1)
        L11:
            r0 = r3
            goto L1e
        L13:
            boolean r3 = r2.c
            if (r3 == 0) goto L1e
            retrofit2.adapter.rxjava3.b r3 = new retrofit2.adapter.rxjava3.b
            r1 = 0
            r3.<init>(r0, r1)
            goto L11
        L1e:
            boolean r3 = r2.d
            if (r3 == 0) goto L29
            io.reactivex.rxjava3.internal.operators.flowable.c r3 = new io.reactivex.rxjava3.internal.operators.flowable.c
            r1 = 1
            r3.<init>(r0, r1)
            return r3
        L29:
            boolean r3 = r2.e
            if (r3 == 0) goto L34
            io.reactivex.rxjava3.internal.operators.flowable.b r3 = new io.reactivex.rxjava3.internal.operators.flowable.b
            r1 = 2
            r3.<init>(r0, r1)
            return r3
        L34:
            boolean r3 = r2.f
            if (r3 == 0) goto L3f
            io.reactivex.rxjava3.internal.operators.maybe.e r3 = new io.reactivex.rxjava3.internal.operators.maybe.e
            r1 = 4
            r3.<init>(r0, r1)
            return r3
        L3f:
            boolean r3 = r2.g
            if (r3 == 0) goto L49
            io.reactivex.rxjava3.internal.operators.observable.Y r3 = new io.reactivex.rxjava3.internal.operators.observable.Y
            r3.<init>(r0)
            return r3
        L49:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: retrofit2.adapter.rxjava3.e.j(retrofit2.u):java.lang.Object");
    }
}
