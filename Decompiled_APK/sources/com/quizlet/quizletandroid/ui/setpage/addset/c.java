package com.quizlet.quizletandroid.ui.setpage.addset;

import io.reactivex.rxjava3.subjects.j;
import java.util.LinkedHashSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class c extends com.quizlet.viewmodel.b {
    public final com.quizlet.infra.legacysyncengine.net.c c;
    public final com.quizlet.quizletandroid.util.a d;
    public final com.quizlet.features.infra.legacyadapter.helper.a e;
    public final LinkedHashSet f;
    public final u g;
    public boolean h;
    public final j i;
    public final com.quizlet.infra.legacysyncengine.datasources.f j;

    public c(com.quizlet.infra.legacysyncengine.net.c loader, com.quizlet.quizletandroid.util.a addSetToClassManager) {
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(addSetToClassManager, "addSetToClassManager");
        this.c = loader;
        this.d = addSetToClassManager;
        this.e = new com.quizlet.features.infra.legacyadapter.helper.a(null);
        this.f = new LinkedHashSet();
        this.g = l.b(new com.quizlet.login.magiclink.ui.e(this, 24));
        j jVar = new j();
        Intrinsics.checkNotNullExpressionValue(jVar, "create(...)");
        this.i = jVar;
        this.j = new com.quizlet.infra.legacysyncengine.datasources.f(this, 8);
    }

    @Override // com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        this.c.a((com.quizlet.infra.legacysyncengine.orm.query.a) this.g.getValue(), this.j);
        super.z();
    }
}
