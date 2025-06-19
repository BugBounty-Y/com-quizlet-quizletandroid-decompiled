package com.quizlet.features.setpage.terms;

import androidx.lifecycle.Y;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.quizletandroid.ui.joincontenttofolder.k;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) ((com.quizlet.data.interactor.set.c) this.c).a;
                ((com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar.a).a(this.b).a((com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar.d);
                io.reactivex.rxjava3.subjects.d dVar = (io.reactivex.rxjava3.subjects.d) aVar.c;
                if (dVar != null) {
                    dVar.onComplete();
                }
                aVar.c = null;
                return;
            default:
                k kVar = (k) this.c;
                ArrayList arrayList = kVar.o;
                if (arrayList == null) {
                    Intrinsics.m("initialClassFolders");
                    throw null;
                }
                LinkedHashSet linkedHashSet = kVar.s;
                if (linkedHashSet == null) {
                    Intrinsics.m("selectedFolderIds");
                    throw null;
                }
                List listW0 = CollectionsKt.w0(linkedHashSet);
                List folderIdsRemoved = CollectionsKt.b0(arrayList, listW0);
                List folderIdsAdded = CollectionsKt.b0(listW0, arrayList);
                com.quizlet.features.notes.a aVar2 = kVar.i;
                aVar2.getClass();
                Intrinsics.checkNotNullParameter(folderIdsAdded, "folderIdsAdded");
                Iterator it2 = folderIdsAdded.iterator();
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    long j = this.b;
                    EventLogger eventLogger = aVar2.a;
                    if (!zHasNext) {
                        Intrinsics.checkNotNullParameter(folderIdsRemoved, "folderIdsRemoved");
                        Iterator it3 = folderIdsRemoved.iterator();
                        while (it3.hasNext()) {
                            EventLoggerExt.c(eventLogger, new com.quizlet.quizletandroid.ui.group.classcontent.logging.a(j, ((Number) it3.next()).longValue(), 3));
                        }
                        Y y = kVar.r;
                        ArrayList arrayList2 = kVar.o;
                        if (arrayList2 == null) {
                            Intrinsics.m("initialClassFolders");
                            throw null;
                        }
                        LinkedHashSet linkedHashSet2 = kVar.s;
                        if (linkedHashSet2 != null) {
                            y.l(new com.quizlet.quizletandroid.ui.joincontenttofolder.b(j, linkedHashSet2, arrayList2));
                            return;
                        } else {
                            Intrinsics.m("selectedFolderIds");
                            throw null;
                        }
                    }
                    EventLoggerExt.c(eventLogger, new com.quizlet.quizletandroid.ui.group.classcontent.logging.a(j, ((Number) it2.next()).longValue(), 2));
                }
        }
    }
}
