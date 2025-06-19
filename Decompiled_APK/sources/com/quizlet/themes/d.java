package com.quizlet.themes;

import androidx.compose.animation.core.J0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final com.quizlet.ui.resources.icons.d a;
    public final com.quizlet.ui.resources.icons.f b;
    public final com.quizlet.ui.resources.icons.e c;
    public final J0 d;
    public final com.quizlet.ui.resources.icons.d e;
    public final com.quizlet.ui.resources.icons.d f;
    public final com.quizlet.ui.resources.icons.d g;

    public d(com.quizlet.ui.resources.icons.f Study, com.quizlet.ui.resources.icons.e Social, J0 Brand, int i) {
        com.quizlet.ui.resources.icons.d System = com.quizlet.ui.resources.icons.d.k;
        Study = (i & 2) != 0 ? com.quizlet.ui.resources.icons.d.j : Study;
        Social = (i & 4) != 0 ? com.quizlet.ui.resources.icons.d.h : Social;
        com.quizlet.ui.resources.icons.d Other = com.quizlet.ui.resources.icons.d.f;
        Brand = (i & 16) != 0 ? com.quizlet.ui.resources.icons.b.c : Brand;
        com.quizlet.ui.resources.icons.d Components = com.quizlet.ui.resources.icons.d.b;
        com.quizlet.ui.resources.icons.d Launcher = com.quizlet.ui.resources.icons.d.d;
        com.quizlet.ui.resources.icons.d Generic = com.quizlet.ui.resources.icons.d.c;
        com.quizlet.ui.resources.icons.d Logo = com.quizlet.ui.resources.icons.d.e;
        Intrinsics.checkNotNullParameter(System, "System");
        Intrinsics.checkNotNullParameter(Study, "Study");
        Intrinsics.checkNotNullParameter(Social, "Social");
        Intrinsics.checkNotNullParameter(Other, "Other");
        Intrinsics.checkNotNullParameter(Brand, "Brand");
        Intrinsics.checkNotNullParameter(Components, "Components");
        Intrinsics.checkNotNullParameter(Launcher, "Launcher");
        Intrinsics.checkNotNullParameter(Generic, "Generic");
        Intrinsics.checkNotNullParameter(Logo, "Logo");
        this.a = System;
        this.b = Study;
        this.c = Social;
        this.d = Brand;
        this.e = Components;
        this.f = Generic;
        this.g = Logo;
    }
}
