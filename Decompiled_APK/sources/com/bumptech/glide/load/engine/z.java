package com.bumptech.glide.load.engine;

import android.os.SystemClock;
import android.util.Log;
import java.util.Collections;
import java.util.Objects;

/* loaded from: classes.dex */
public final class z implements f, e {
    public final g a;
    public final h b;
    public volatile int c;
    public volatile c d;
    public volatile Object e;
    public volatile com.bumptech.glide.load.model.q f;
    public volatile d g;

    public z(g gVar, h hVar) {
        this.a = gVar;
        this.b = hVar;
    }

    @Override // com.bumptech.glide.load.engine.e
    public final void a(com.bumptech.glide.load.e eVar, Object obj, com.bumptech.glide.load.data.e eVar2, int i, com.bumptech.glide.load.e eVar3) {
        this.b.a(eVar, obj, eVar2, this.f.c.g(), eVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0017  */
    @Override // com.bumptech.glide.load.engine.f
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b() {
        /*
            r7 = this;
            java.lang.Object r0 = r7.e
            r1 = 0
            r2 = 1
            if (r0 == 0) goto L17
            java.lang.Object r0 = r7.e
            r7.e = r1
            boolean r0 = r7.d(r0)     // Catch: java.io.IOException -> L11
            if (r0 != 0) goto L17
            goto L23
        L11:
            java.lang.String r0 = "SourceGenerator"
            r3 = 3
            android.util.Log.isLoggable(r0, r3)
        L17:
            com.bumptech.glide.load.engine.c r0 = r7.d
            if (r0 == 0) goto L24
            com.bumptech.glide.load.engine.c r0 = r7.d
            boolean r0 = r0.b()
            if (r0 == 0) goto L24
        L23:
            return r2
        L24:
            r7.d = r1
            r7.f = r1
            r0 = 0
        L29:
            if (r0 != 0) goto L89
            int r1 = r7.c
            com.bumptech.glide.load.engine.g r3 = r7.a
            java.util.ArrayList r3 = r3.b()
            int r3 = r3.size()
            if (r1 >= r3) goto L89
            com.bumptech.glide.load.engine.g r1 = r7.a
            java.util.ArrayList r1 = r1.b()
            int r3 = r7.c
            int r4 = r3 + 1
            r7.c = r4
            java.lang.Object r1 = r1.get(r3)
            com.bumptech.glide.load.model.q r1 = (com.bumptech.glide.load.model.q) r1
            r7.f = r1
            com.bumptech.glide.load.model.q r1 = r7.f
            if (r1 == 0) goto L29
            com.bumptech.glide.load.engine.g r1 = r7.a
            com.bumptech.glide.load.engine.j r1 = r1.p
            com.bumptech.glide.load.model.q r3 = r7.f
            com.bumptech.glide.load.data.e r3 = r3.c
            int r3 = r3.g()
            boolean r1 = r1.a(r3)
            if (r1 != 0) goto L73
            com.bumptech.glide.load.engine.g r1 = r7.a
            com.bumptech.glide.load.model.q r3 = r7.f
            com.bumptech.glide.load.data.e r3 = r3.c
            java.lang.Class r3 = r3.getDataClass()
            com.bumptech.glide.load.engine.t r1 = r1.c(r3)
            if (r1 == 0) goto L29
        L73:
            com.bumptech.glide.load.model.q r0 = r7.f
            com.bumptech.glide.load.model.q r1 = r7.f
            com.bumptech.glide.load.data.e r1 = r1.c
            com.bumptech.glide.load.engine.g r3 = r7.a
            com.bumptech.glide.g r3 = r3.o
            com.quizlet.data.interactor.school.b r4 = new com.quizlet.data.interactor.school.b
            r5 = 7
            r6 = 0
            r4.<init>(r7, r6, r0, r5)
            r1.h(r3, r4)
            r0 = r2
            goto L29
        L89:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.engine.z.b():boolean");
    }

    @Override // com.bumptech.glide.load.engine.e
    public final void c(com.bumptech.glide.load.e eVar, Exception exc, com.bumptech.glide.load.data.e eVar2, int i) {
        this.b.c(eVar, exc, eVar2, this.f.c.g());
    }

    @Override // com.bumptech.glide.load.engine.f
    public final void cancel() {
        com.bumptech.glide.load.model.q qVar = this.f;
        if (qVar != null) {
            qVar.c.cancel();
        }
    }

    public final boolean d(Object obj) throws Throwable {
        Throwable th;
        int i = com.bumptech.glide.util.h.a;
        SystemClock.elapsedRealtimeNanos();
        boolean z = false;
        try {
            com.bumptech.glide.load.data.g gVarG = this.a.c.a().g(obj);
            Object objL = gVarG.l();
            com.bumptech.glide.load.b bVarD = this.a.d(objL);
            com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a(bVarD, objL, this.a.i);
            com.bumptech.glide.load.e eVar = this.f.a;
            g gVar = this.a;
            d dVar = new d(eVar, gVar.n);
            com.bumptech.glide.load.engine.cache.a aVarA = gVar.h.a();
            aVarA.d(dVar, aVar);
            if (Log.isLoggable("SourceGenerator", 2)) {
                dVar.toString();
                obj.toString();
                bVarD.toString();
                SystemClock.elapsedRealtimeNanos();
            }
            if (aVarA.c(dVar) != null) {
                this.g = dVar;
                this.d = new c(Collections.singletonList(this.f.a), this.a, this);
                this.f.c.f();
                return true;
            }
            if (Log.isLoggable("SourceGenerator", 3)) {
                Objects.toString(this.g);
                obj.toString();
            }
            try {
                this.b.a(this.f.a, gVarG.l(), this.f.c, this.f.c.g(), this.f.a);
                return false;
            } catch (Throwable th2) {
                th = th2;
                z = true;
                if (z) {
                    throw th;
                }
                this.f.c.f();
                throw th;
            }
        } catch (Throwable th3) {
            th = th3;
        }
    }
}
