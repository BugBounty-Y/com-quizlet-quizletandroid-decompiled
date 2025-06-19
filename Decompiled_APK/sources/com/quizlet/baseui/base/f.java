package com.quizlet.baseui.base;

import android.os.Bundle;
import android.widget.FrameLayout;
import androidx.appcompat.widget.Toolbar;
import com.google.android.material.tabs.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class f extends b {
    public androidx.viewbinding.a k;

    public FrameLayout J() {
        return null;
    }

    public final androidx.viewbinding.a K() {
        androidx.viewbinding.a aVar = this.k;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("binding");
        throw null;
    }

    public l L() {
        return null;
    }

    public Toolbar M() {
        return null;
    }

    public abstract androidx.viewbinding.a N();

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        androidx.viewbinding.a aVarN = N();
        Intrinsics.checkNotNullParameter(aVarN, "<set-?>");
        this.k = aVarN;
        setContentView(K().getRoot());
        Toolbar toolbarM = M();
        if (toolbarM != null) {
            this.f = toolbarM;
        }
        l lVarL = L();
        if (lVarL != null) {
            this.g = lVarL;
        }
        FrameLayout frameLayoutJ = J();
        if (frameLayoutJ != null) {
            this.h = frameLayoutJ;
        }
        setVolumeControlStream(3);
        FrameLayout frameLayout = this.h;
        if (frameLayout == null) {
            return;
        }
        frameLayout.setVisibility(8);
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return 0;
    }
}
