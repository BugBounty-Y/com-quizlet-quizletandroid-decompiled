package com.quizlet.features.setpage.viewmodel;

import android.widget.TextView;
import androidx.lifecycle.Y;
import com.quizlet.data.model.C4123e0;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.C4756b;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.DiagramMatchGameFragment;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.viewmodel.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4430d implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C4430d(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                ((P) this.b).d1.j(com.quizlet.features.setpage.screenstates.p.a);
                ((com.braze.push.g) this.c).invoke();
                return;
            case 1:
                ((io.reactivex.rxjava3.core.i) this.b).c(new com.quizlet.infra.legacysyncengine.utils.b((io.reactivex.rxjava3.subjects.p) this.c, 0));
                return;
            case 2:
                ((com.quizlet.infra.legacysyncengine.net.request.f) this.b).c.remove((IdMappedQuery) this.c);
                return;
            case 3:
                com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar = (com.quizlet.quizletandroid.ui.joincontenttofolder.k) this.b;
                Y y = kVar.r;
                List list = kVar.n;
                if (list == null) {
                    Intrinsics.m("initialFolderSets");
                    throw null;
                }
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((C4123e0) it2.next()).c));
                }
                LinkedHashSet linkedHashSet = kVar.s;
                if (linkedHashSet != null) {
                    y.l(new com.quizlet.quizletandroid.ui.joincontenttofolder.n((List) this.c, linkedHashSet, arrayList));
                    return;
                } else {
                    Intrinsics.m("selectedFolderIds");
                    throw null;
                }
            case 4:
                ((TextView) this.b).setTextColor(((C4756b) this.c).j);
                return;
            default:
                DiagramMatchGameFragment diagramMatchGameFragment = (DiagramMatchGameFragment) this.b;
                diagramMatchGameFragment.s = true;
                diagramMatchGameFragment.U((ArrayList) this.c);
                return;
        }
    }
}
