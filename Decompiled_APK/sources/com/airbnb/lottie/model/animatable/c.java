package com.airbnb.lottie.model.animatable;

import com.airbnb.lottie.animation.keyframe.j;
import com.airbnb.lottie.animation.keyframe.m;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class c implements f {
    public final ArrayList a;

    public c() {
        this.a = new ArrayList();
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public com.airbnb.lottie.animation.keyframe.e j() {
        ArrayList arrayList = this.a;
        return ((com.airbnb.lottie.value.a) arrayList.get(0)).c() ? new j(arrayList, 1) : new m(arrayList);
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public List k() {
        return this.a;
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public boolean l() {
        ArrayList arrayList = this.a;
        return arrayList.size() == 1 && ((com.airbnb.lottie.value.a) arrayList.get(0)).c();
    }

    public c(ArrayList arrayList) {
        this.a = arrayList;
    }
}
