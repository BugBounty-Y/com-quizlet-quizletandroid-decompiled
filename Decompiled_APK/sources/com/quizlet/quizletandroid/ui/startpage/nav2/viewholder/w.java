package com.quizlet.quizletandroid.ui.startpage.nav2.viewholder;

import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.LearnSettingsUpdateData;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;

/* loaded from: classes3.dex */
public final /* synthetic */ class w implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ w(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Exception {
        switch (this.a) {
            case 0:
                Y y = (Y) this.b;
                if (y != null) {
                    y.r1.j(new com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.x(((DBStudySet) this.c).getId(), (Integer) this.d));
                }
                break;
            case 1:
                ((com.quizlet.assembly.compose.modals.x) this.b).a();
                ((Function1) this.c).invoke(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.e((LearnSettingsUpdateData) this.d));
                break;
            case 2:
                ((Function1) this.b).invoke(LearnSettingsUpdateData.a((LearnSettingsUpdateData) this.c, false, false, false, false, false, false, false, false, false, null, 3583));
                ((Function1) this.d).invoke(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.b.a);
                break;
            case 3:
                com.quizlet.quizletandroid.util.a aVar = (com.quizlet.quizletandroid.util.a) this.b;
                aVar.getClass();
                List list = (List) this.c;
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    ((DBGroupSet) it2.next()).setDeleted(true);
                }
                List list2 = (List) this.d;
                Iterator it3 = list2.iterator();
                while (it3.hasNext()) {
                    ((DBGroupSet) it3.next()).setDeleted(false);
                }
                aVar.a.b(CollectionsKt.c0(list, list2));
                break;
            default:
                if (!((F) this.b).a) {
                    ((Function0) this.c).invoke();
                }
                ((com.quizlet.assembly.compose.modals.x) this.d).a();
                break;
        }
        return Unit.a;
    }
}
