package com.quizlet.quizletandroid.ui.diagramming;

import android.content.Context;
import com.fasterxml.jackson.databind.ObjectWriter;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j {
    public final Context a;
    public final ObjectWriter b;
    public final io.reactivex.rxjava3.subjects.j c;
    public final io.reactivex.rxjava3.subjects.j d;
    public LinkedHashSet e;
    public DiagramView f;

    public j(Context context, ObjectWriter objectWriter) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(objectWriter, "objectWriter");
        this.a = context;
        this.b = objectWriter;
        io.reactivex.rxjava3.subjects.j jVar = new io.reactivex.rxjava3.subjects.j();
        Intrinsics.checkNotNullExpressionValue(jVar, "create(...)");
        this.c = jVar;
        io.reactivex.rxjava3.subjects.j jVar2 = new io.reactivex.rxjava3.subjects.j();
        Intrinsics.checkNotNullExpressionValue(jVar2, "create(...)");
        this.d = jVar2;
        this.e = new LinkedHashSet();
    }

    public final void a(String str) {
        DiagramView diagramView = this.f;
        if (diagramView != null) {
            diagramView.e("javascript:".concat(str));
        } else {
            Intrinsics.m("view");
            throw null;
        }
    }
}
