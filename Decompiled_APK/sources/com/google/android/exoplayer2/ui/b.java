package com.google.android.exoplayer2.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class b extends View implements f {
    public final ArrayList a;
    public List b;
    public float c;

    public b(Context context) {
        this(context, 0);
    }

    @Override // com.google.android.exoplayer2.ui.f
    public final void a(List list, c cVar, float f, float f2) {
        this.b = list;
        this.c = f;
        while (true) {
            ArrayList arrayList = this.a;
            if (arrayList.size() >= list.size()) {
                invalidate();
                return;
            }
            arrayList.add(new e(getContext()));
        }
    }

    @Override // android.view.View
    public final void dispatchDraw(Canvas canvas) {
        List list = this.b;
        if (list.isEmpty()) {
            return;
        }
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        int width = getWidth() - getPaddingRight();
        int paddingBottom = height - getPaddingBottom();
        if (paddingBottom <= paddingTop || width <= paddingLeft) {
            return;
        }
        int i = paddingBottom - paddingTop;
        float f = this.c;
        if ((f != -3.4028235E38f ? f * i : -3.4028235E38f) > DefinitionKt.NO_Float_VALUE && list.size() > 0) {
            list.get(0).getClass();
            throw new ClassCastException();
        }
    }

    public b(Context context, int i) {
        super(context, null);
        this.a = new ArrayList();
        this.b = Collections.EMPTY_LIST;
        this.c = 0.0533f;
    }
}
