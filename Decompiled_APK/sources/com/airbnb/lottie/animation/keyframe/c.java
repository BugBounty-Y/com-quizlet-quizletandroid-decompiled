package com.airbnb.lottie.animation.keyframe;

import android.os.Handler;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

/* loaded from: classes.dex */
public final class c implements b, com.iab.omid.library.amazon.internal.d {
    public static c e;
    public float a;
    public final Object b;
    public Object c;
    public Object d;

    public c(com.google.firebase.perf.logging.b bVar, com.google.firebase.heartbeatinfo.e eVar) {
        this.a = DefinitionKt.NO_Float_VALUE;
        this.b = eVar;
    }

    public static c d() {
        if (e == null) {
            e = new c(new com.google.firebase.perf.logging.b(21), new com.google.firebase.heartbeatinfo.e(21));
        }
        return e;
    }

    @Override // com.iab.omid.library.amazon.internal.d
    public void a(boolean z) {
        if (z) {
            com.iab.omid.library.amazon.walking.a.g.getClass();
            com.iab.omid.library.amazon.walking.a.b();
            return;
        }
        com.iab.omid.library.amazon.walking.a.g.getClass();
        Handler handler = com.iab.omid.library.amazon.walking.a.i;
        if (handler != null) {
            handler.removeCallbacks(com.iab.omid.library.amazon.walking.a.k);
            com.iab.omid.library.amazon.walking.a.i = null;
        }
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public com.airbnb.lottie.value.a b() {
        return (com.airbnb.lottie.value.a) this.c;
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean c(float f) {
        com.airbnb.lottie.value.a aVar = (com.airbnb.lottie.value.a) this.c;
        if (f >= aVar.b() && f < aVar.a()) {
            return !((com.airbnb.lottie.value.a) this.c).c();
        }
        this.c = f(f);
        return true;
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public float e() {
        return ((com.airbnb.lottie.value.a) ((List) this.b).get(r0.size() - 1)).a();
    }

    public com.airbnb.lottie.value.a f(float f) {
        List list = (List) this.b;
        com.airbnb.lottie.value.a aVar = (com.airbnb.lottie.value.a) list.get(list.size() - 1);
        if (f >= aVar.b()) {
            return aVar;
        }
        for (int size = list.size() - 2; size >= 1; size--) {
            com.airbnb.lottie.value.a aVar2 = (com.airbnb.lottie.value.a) list.get(size);
            if (((com.airbnb.lottie.value.a) this.c) != aVar2 && f >= aVar2.b() && f < aVar2.a()) {
                return aVar2;
            }
        }
        return (com.airbnb.lottie.value.a) list.get(0);
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public float i() {
        return ((com.airbnb.lottie.value.a) ((List) this.b).get(0)).b();
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean isEmpty() {
        return false;
    }

    public c(List list) {
        this.d = null;
        this.a = -1.0f;
        this.b = list;
        this.c = f(DefinitionKt.NO_Float_VALUE);
    }

    @Override // com.airbnb.lottie.animation.keyframe.b
    public boolean a(float f) {
        com.airbnb.lottie.value.a aVar = (com.airbnb.lottie.value.a) this.d;
        com.airbnb.lottie.value.a aVar2 = (com.airbnb.lottie.value.a) this.c;
        if (aVar == aVar2 && this.a == f) {
            return true;
        }
        this.d = aVar2;
        this.a = f;
        return false;
    }
}
