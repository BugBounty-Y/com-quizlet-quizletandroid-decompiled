package com.quizlet.quizletandroid;

import android.os.Bundle;
import androidx.camera.camera2.internal.c0;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.quizletandroid.ui.startpage.nav2.RecommendationsActionOptionsFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements dagger.android.a {
    public final u a;
    public final C4624g b;
    public final C4622e c;
    public Long d;
    public Integer e;

    public m(u uVar, C4624g c4624g, C4622e c4622e) {
        this.a = uVar;
        this.b = c4624g;
        this.c = c4622e;
    }

    @Override // dagger.android.a
    public final dagger.android.b create(Object obj) {
        RecommendationsActionOptionsFragment instance = (RecommendationsActionOptionsFragment) obj;
        Intrinsics.checkNotNullParameter(instance, "instance");
        Bundle arguments = instance.getArguments();
        if (arguments != null) {
            this.d = Long.valueOf(arguments.getLong("setID", 0L));
            this.e = Integer.valueOf(arguments.getInt("recsSectionNumber", -1));
        }
        S6.a(Long.class, this.d);
        S6.a(Integer.class, this.e);
        return new c0(this.a, this.b, this.c, this.d, this.e);
    }
}
