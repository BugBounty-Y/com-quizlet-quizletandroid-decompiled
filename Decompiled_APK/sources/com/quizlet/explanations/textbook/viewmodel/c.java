package com.quizlet.explanations.textbook.viewmodel;

import androidx.compose.animation.d0;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.u0;
import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.Section;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.data.model.Textbook;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.explanations.textbook.chaptermenu.data.d;
import com.quizlet.explanations.textbook.chaptermenu.data.e;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.data.m;
import com.quizlet.explanations.textbook.data.n;
import com.quizlet.explanations.textbook.data.o;
import com.quizlet.explanations.textbook.data.q;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class c extends com.quizlet.viewmodel.b {
    public final ExplanationsLogger c;
    public final com.quizlet.data.repository.searchexplanations.c d;
    public final SearchEventLogger e;
    public final androidx.work.impl.model.c f;
    public final com.quizlet.viewmodel.livedata.b g;
    public final X h;
    public final Y i;
    public final X j;
    public final Y k;
    public TextbookSetUpState l;
    public Textbook m;
    public final C4927s n;

    public c(ExplanationsLogger explanationsLogger, com.quizlet.data.repository.searchexplanations.c shareExplanationsHelper, SearchEventLogger searchEventLogger, androidx.work.impl.model.c userProperties, FolderLogger folderEventLogger) {
        Intrinsics.checkNotNullParameter(explanationsLogger, "explanationsLogger");
        Intrinsics.checkNotNullParameter(shareExplanationsHelper, "shareExplanationsHelper");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.c = explanationsLogger;
        this.d = shareExplanationsHelper;
        this.e = searchEventLogger;
        this.f = userProperties;
        this.g = new com.quizlet.viewmodel.livedata.b();
        this.h = new X(1);
        this.i = new Y();
        this.j = new X(1);
        this.k = new Y();
        this.n = new C4927s();
        folderEventLogger.setScreenName("expert_solutions_textbook");
    }

    public final void B(TableOfContentItem item) {
        e dVar;
        String strN;
        Intrinsics.checkNotNullParameter(item, "content");
        if (item instanceof Chapter) {
            dVar = new com.quizlet.explanations.textbook.chaptermenu.data.b((Chapter) item);
        } else if (item instanceof ExerciseGroup) {
            dVar = new com.quizlet.explanations.textbook.chaptermenu.data.c((ExerciseGroup) item);
        } else {
            if (!(item instanceof Section)) {
                throw new IllegalStateException("This should never happen: content (" + item + ")");
            }
            dVar = new d((Section) item);
        }
        this.n.addLast(dVar);
        long jB = dVar.a().b();
        if (dVar instanceof com.quizlet.explanations.textbook.chaptermenu.data.b) {
            strN = d0.n(jB, "Chapter-");
        } else if (dVar instanceof d) {
            strN = d0.n(jB, "Section-");
        } else {
            if (!(dVar instanceof com.quizlet.explanations.textbook.chaptermenu.data.c)) {
                throw new NoWhenBranchMatchedException();
            }
            strN = d0.n(jB, "ExerciseGroup-");
        }
        Textbook textbook = this.m;
        this.h.j(new m(strN, textbook != null ? textbook.f : false));
        Textbook textbook2 = this.m;
        if (textbook2 == null) {
            return;
        }
        ExplanationsLogger.EventData.Textbook textbook3 = new ExplanationsLogger.EventData.Textbook(textbook2.a, textbook2.b);
        ExplanationsLogger explanationsLogger = this.c;
        explanationsLogger.getClass();
        Intrinsics.checkNotNullParameter(textbook3, "textbook");
        Intrinsics.checkNotNullParameter(item, "item");
        ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
        u0 u0Var = new u0(13, item, textbook3);
        companion.getClass();
        explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_textbook_toc_click_content_item", u0Var));
    }

    public final void C(String id, boolean z) {
        Intrinsics.checkNotNullParameter(id, "id");
        ExerciseDetailSetupState deepLink = z ? new ExerciseDetailSetupState.DeepLink(id) : new ExerciseDetailSetupState.Textbook(id);
        this.g.n();
        boolean z2 = deepLink instanceof ExerciseDetailSetupState.DeepLink;
        this.h.j(new n(deepLink, !z2, z2));
        Textbook textbook = this.m;
        if (textbook == null) {
            return;
        }
        ExplanationsLogger.EventData.Exercise eventData = new ExplanationsLogger.EventData.Exercise(textbook.a, textbook.b, id);
        ExplanationsLogger explanationsLogger = this.c;
        explanationsLogger.getClass();
        Intrinsics.checkNotNullParameter(eventData, "eventData");
        ExplanationsEventLog.Companion companion = ExplanationsEventLog.b;
        com.quizlet.eventlogger.features.explanations.b bVar = new com.quizlet.eventlogger.features.explanations.b(explanationsLogger, eventData, 1);
        companion.getClass();
        explanationsLogger.a(ExplanationsEventLog.Companion.a("explanations_textbook_toc_click_exercise_item", bVar));
        this.e.i(eventData.getIsbn(), eventData.getExerciseId());
    }

    public final void D() {
        this.g.o(q.a);
    }

    public final void E(TextbookSetUpState textbookSetUpState) {
        final int i = 0;
        Function1 onTableOfContents = new Function1(this) { // from class: com.quizlet.explanations.textbook.viewmodel.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                String isbn = (String) obj;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(isbn, "isbn");
                        c cVar = this.b;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(isbn, "isbn");
                        cVar.g.n();
                        cVar.h.j(new o(isbn));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(isbn, "id");
                        ExerciseDetailSetupState.DeepLink deepLink = new ExerciseDetailSetupState.DeepLink(isbn);
                        c cVar2 = this.b;
                        cVar2.g.n();
                        cVar2.h.j(new n(deepLink, false, true));
                        break;
                }
                return Unit.a;
            }
        };
        final int i2 = 1;
        Function1 onExercise = new Function1(this) { // from class: com.quizlet.explanations.textbook.viewmodel.a
            public final /* synthetic */ c b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                String isbn = (String) obj;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(isbn, "isbn");
                        c cVar = this.b;
                        cVar.getClass();
                        Intrinsics.checkNotNullParameter(isbn, "isbn");
                        cVar.g.n();
                        cVar.h.j(new o(isbn));
                        break;
                    default:
                        Intrinsics.checkNotNullParameter(isbn, "id");
                        ExerciseDetailSetupState.DeepLink deepLink = new ExerciseDetailSetupState.DeepLink(isbn);
                        c cVar2 = this.b;
                        cVar2.g.n();
                        cVar2.h.j(new n(deepLink, false, true));
                        break;
                }
                return Unit.a;
            }
        };
        textbookSetUpState.getClass();
        Intrinsics.checkNotNullParameter(onTableOfContents, "onTableOfContents");
        Intrinsics.checkNotNullParameter(onExercise, "onExercise");
        if (textbookSetUpState instanceof TextbookSetUpState.TableOfContents) {
            onTableOfContents.invoke(((TextbookSetUpState.TableOfContents) textbookSetUpState).a);
        } else {
            if (!(textbookSetUpState instanceof TextbookSetUpState.Exercise)) {
                throw new NoWhenBranchMatchedException();
            }
            onExercise.invoke(((TextbookSetUpState.Exercise) textbookSetUpState).a);
        }
    }
}
