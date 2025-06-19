package com.quizlet.quizletandroid.ui.activitycenter.views;

import android.content.Context;
import android.util.AttributeSet;
import android.util.SparseArray;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes3.dex */
public abstract class c extends ConstraintLayout {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(Context context, AttributeSet attributeSet) throws XmlPullParserException, IOException {
        super(context, attributeSet, 0, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = new SparseArray();
        this.b = new ArrayList(4);
        this.c = new androidx.constraintlayout.core.widgets.f();
        this.d = 0;
        this.e = 0;
        this.f = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.g = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.h = true;
        this.i = 257;
        this.j = null;
        this.k = null;
        this.l = -1;
        this.m = new HashMap();
        this.n = new SparseArray();
        this.o = new androidx.constraintlayout.widget.f(this, this);
        j(attributeSet, 0);
    }

    public abstract void setBadgeBackground(int i);
}
