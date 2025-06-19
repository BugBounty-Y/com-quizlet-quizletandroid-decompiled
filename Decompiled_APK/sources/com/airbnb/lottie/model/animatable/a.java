package com.airbnb.lottie.model.animatable;

import androidx.compose.animation.core.J0;
import com.airbnb.lottie.animation.keyframe.j;
import com.airbnb.lottie.animation.keyframe.n;
import java.util.List;

/* loaded from: classes.dex */
public final class a extends J0 {
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(List list, int i) {
        super(list);
        this.c = i;
    }

    @Override // com.airbnb.lottie.model.animatable.f
    public final com.airbnb.lottie.animation.keyframe.e j() {
        switch (this.c) {
            case 0:
                return new com.airbnb.lottie.animation.keyframe.f((List) this.b, 0);
            case 1:
                return new j((List) this.b, 0);
            case 2:
                return new com.airbnb.lottie.animation.keyframe.f((List) this.b, 1);
            case 3:
                return new j((List) this.b, 1);
            case 4:
                return new j((List) this.b, 2);
            case 5:
                return new n((List) this.b);
            default:
                return new com.airbnb.lottie.animation.keyframe.f((List) this.b, 2);
        }
    }
}
