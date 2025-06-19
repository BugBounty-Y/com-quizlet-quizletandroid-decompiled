package com.quizlet.quizletandroid.ui.globalnav.composable;

import android.content.Context;
import android.content.Intent;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.cardview.widget.CardView;
import androidx.lifecycle.Y;
import androidx.lifecycle.p0;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3514p4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B;
import com.quizlet.data.model.EnumC4164s0;
import com.quizlet.data.model.Y1;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.generated.enums.EnumC4525u1;
import com.quizlet.generated.enums.w1;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4611o;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.joincontenttofolder.SelectableFolderListFragment;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import com.quizlet.quizletandroid.ui.library.M;
import com.quizlet.quizletandroid.ui.library.N;
import com.quizlet.quizletandroid.ui.library.O;
import com.quizlet.quizletandroid.ui.library.P;
import com.quizlet.quizletandroid.ui.library.W;
import com.quizlet.quizletandroid.ui.library.X;
import com.quizlet.quizletandroid.ui.library.Z;
import com.quizlet.quizletandroid.ui.library.a0;
import com.quizlet.quizletandroid.ui.library.b0;
import com.quizlet.quizletandroid.ui.library.c0;
import com.quizlet.quizletandroid.ui.library.data.C4656j;
import com.quizlet.quizletandroid.ui.library.data.C4657k;
import com.quizlet.quizletandroid.ui.library.data.C4658l;
import com.quizlet.quizletandroid.ui.library.data.C4659m;
import com.quizlet.quizletandroid.ui.library.data.J;
import com.quizlet.quizletandroid.ui.library.data.L;
import com.quizlet.quizletandroid.ui.login.SignUpWallModalFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class s extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ s(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    /* JADX WARN: Type inference failed for: r2v27, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z;
        int i;
        w1 w1Var;
        s0 s0Var;
        Object value;
        Object value2;
        Object value3;
        s0 s0Var2;
        Object value4;
        com.quizlet.quizletandroid.ui.login.viewmodels.a aVar = com.quizlet.quizletandroid.ui.login.viewmodels.a.a;
        com.quizlet.quizletandroid.ui.login.viewmodels.c cVar = com.quizlet.quizletandroid.ui.login.viewmodels.c.a;
        int i2 = 16;
        String string = null;
        switch (this.a) {
            case 0:
                String p0 = (String) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).E(p0);
                return Unit.a;
            case 1:
                com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.h p02 = (com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.h) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ClassContentListFragment classContentListFragment = (ClassContentListFragment) this.receiver;
                String str = ClassContentListFragment.n;
                ((C4611o) classContentListFragment.J()).b.setVisibility(8);
                ((C4611o) classContentListFragment.J()).c.setVisibility(8);
                CardView cardView = classContentListFragment.m;
                if (cardView != null) {
                    cardView.setVisibility(8);
                }
                if (p02 instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.f) {
                    classContentListFragment.T(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(classContentListFragment, 5));
                } else if (p02 instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.g) {
                    com.quizlet.features.infra.legacyadapter.databinding.f fVarA = com.quizlet.features.infra.legacyadapter.databinding.f.a(classContentListFragment.T(new com.braze.ui.inappmessage.f(19)));
                    Intrinsics.checkNotNullExpressionValue(fVarA, "bind(...)");
                    ((QButton) fVarA.c).setVisibility(8);
                    ((QTextView) fVarA.d).setText(R.string.nav2_empty_class_header_does_not_allow_add_set);
                    ((QTextView) fVarA.e).setText(R.string.nav2_empty_class_message_does_not_allow_add_set);
                } else {
                    if (!(p02 instanceof com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.e)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    ArrayList arrayList = ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.e) p02).a;
                    ((C4611o) classContentListFragment.J()).c.setVisibility(0);
                    com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar2 = classContentListFragment.l;
                    if (aVar2 == null) {
                        Intrinsics.m("adapter");
                        throw null;
                    }
                    aVar2.f(arrayList);
                }
                return Unit.a;
            case 2:
                long jLongValue = ((Number) obj).longValue();
                com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar = ((SelectableFolderListFragment) this.receiver).t;
                if (kVar == null) {
                    Intrinsics.m("viewModel");
                    throw null;
                }
                LinkedHashSet linkedHashSet = kVar.s;
                if (linkedHashSet == null) {
                    Intrinsics.m("selectedFolderIds");
                    throw null;
                }
                Long lValueOf = Long.valueOf(jLongValue);
                if (!linkedHashSet.remove(lValueOf)) {
                    linkedHashSet.add(lValueOf);
                }
                Y y = kVar.r;
                List list = kVar.p;
                if (list == null) {
                    Intrinsics.m("allFoldersWithCreator");
                    throw null;
                }
                LinkedHashSet linkedHashSet2 = kVar.s;
                if (linkedHashSet2 != null) {
                    y.l(com.quizlet.quizletandroid.ui.joincontenttofolder.k.C(linkedHashSet2, list));
                    return Unit.a;
                }
                Intrinsics.m("selectedFolderIds");
                throw null;
            case 3:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                com.quizlet.quizletandroid.ui.joincontenttofolder.k kVar2 = (com.quizlet.quizletandroid.ui.joincontenttofolder.k) this.receiver;
                if (zBooleanValue) {
                    kVar2.D();
                } else {
                    kVar2.getClass();
                }
                return Unit.a;
            case 4:
                int iIntValue = ((Number) obj).intValue();
                c0 c0Var = (c0) ((InterfaceC4646d) this.receiver);
                s0 s0Var3 = c0Var.t;
                EnumC4164s0 enumC4164s0 = (EnumC4164s0) ((J) s0Var3.getValue()).a.get(iIntValue);
                int iOrdinal = enumC4164s0.ordinal();
                com.quizlet.library.logging.b bVar = c0Var.i;
                if (iOrdinal == 0) {
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_sets", new com.quizlet.features.universaluploadflow.flashcards.d(13), 6));
                } else if (iOrdinal == 1) {
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_magic_notes", new com.quizlet.features.universaluploadflow.flashcards.d(10), 6));
                } else if (iOrdinal == 2) {
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_folders", new com.quizlet.features.universaluploadflow.flashcards.d(17), 6));
                } else if (iOrdinal == 3) {
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_classes", new com.quizlet.features.universaluploadflow.flashcards.d(12), 6));
                } else if (iOrdinal == 4) {
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_practice_tests", new com.quizlet.features.universaluploadflow.flashcards.d(18), 6));
                } else {
                    if (iOrdinal != 5) {
                        throw new NoWhenBranchMatchedException();
                    }
                    bVar.getClass();
                    bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_tab_your_solutions", new com.quizlet.features.universaluploadflow.flashcards.d(14), 6));
                }
                while (true) {
                    Object value5 = s0Var3.getValue();
                    EnumC4164s0 enumC4164s02 = enumC4164s0;
                    if (s0Var3.k(value5, J.a((J) value5, null, enumC4164s0, null, null, null, false, false, false, 253))) {
                        E.A(p0.j(c0Var), null, null, new b0(enumC4164s02, c0Var, null), 3);
                        return Unit.a;
                    }
                    enumC4164s0 = enumC4164s02;
                }
            case 5:
                EnumC4164s0 tab = (EnumC4164s0) obj;
                Intrinsics.checkNotNullParameter(tab, "p0");
                c0 c0Var2 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var2.getClass();
                Intrinsics.checkNotNullParameter(tab, "tab");
                E.A(p0.j(c0Var2), null, null, new N(tab, c0Var2, null), 3);
                return Unit.a;
            case 6:
                String noteId = (String) obj;
                Intrinsics.checkNotNullParameter(noteId, "p0");
                c0 c0Var3 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var3.getClass();
                Intrinsics.checkNotNullParameter(noteId, "noteId");
                com.quizlet.library.logging.b bVar2 = c0Var3.i;
                bVar2.getClass();
                Intrinsics.checkNotNullParameter(noteId, "noteId");
                bVar2.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_magic_notes", new com.quizlet.library.logging.a(noteId, 2), 6));
                c0Var3.C(20, noteId);
                E.A(p0.j(c0Var3), null, null, new W(c0Var3, noteId, null), 3);
                return Unit.a;
            case 7:
                String questionBankId = (String) obj;
                Intrinsics.checkNotNullParameter(questionBankId, "p0");
                c0 c0Var4 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var4.getClass();
                Intrinsics.checkNotNullParameter(questionBankId, "questionBankUuid");
                com.quizlet.library.logging.b bVar3 = c0Var4.i;
                bVar3.getClass();
                Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
                bVar3.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_question_bank_item", new com.quizlet.library.logging.a(questionBankId, 0), 6));
                c0Var4.C(29, questionBankId);
                E.A(p0.j(c0Var4), null, null, new X(c0Var4, questionBankId, null), 3);
                return Unit.a;
            case 8:
                String isbn = (String) obj;
                Intrinsics.checkNotNullParameter(isbn, "p0");
                c0 c0Var5 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var5.getClass();
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                com.quizlet.library.logging.b bVar4 = c0Var5.i;
                bVar4.getClass();
                Intrinsics.checkNotNullParameter(isbn, "isbn");
                bVar4.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_textbook_item", new com.quizlet.library.logging.a(isbn, 3), 6));
                c0Var5.C(14, isbn);
                E.A(p0.j(c0Var5), null, null, new Z(c0Var5, isbn, null), 3);
                return Unit.a;
            case 9:
                String mediaExerciseId = (String) obj;
                Intrinsics.checkNotNullParameter(mediaExerciseId, "p0");
                c0 c0Var6 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var6.getClass();
                Intrinsics.checkNotNullParameter(mediaExerciseId, "exerciseId");
                com.quizlet.library.logging.b bVar5 = c0Var6.i;
                bVar5.getClass();
                Intrinsics.checkNotNullParameter(mediaExerciseId, "mediaExerciseId");
                bVar5.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_textbook_exercise_item", new com.quizlet.library.logging.a(mediaExerciseId, 1), 6));
                c0Var6.C(15, mediaExerciseId);
                E.A(p0.j(c0Var6), null, null, new a0(c0Var6, mediaExerciseId, null), 3);
                return Unit.a;
            case 10:
                String questionUuid = (String) obj;
                Intrinsics.checkNotNullParameter(questionUuid, "p0");
                c0 c0Var7 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var7.getClass();
                Intrinsics.checkNotNullParameter(questionUuid, "questionId");
                com.quizlet.library.logging.b bVar6 = c0Var7.i;
                bVar6.getClass();
                Intrinsics.checkNotNullParameter(questionUuid, "questionUuid");
                bVar6.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_your_library_explanation_question_item", new com.quizlet.library.logging.a(questionUuid, 4), 6));
                c0Var7.C(16, questionUuid);
                E.A(p0.j(c0Var7), null, null, new O(c0Var7, questionUuid, null), 3);
                return Unit.a;
            case 11:
                com.quizlet.quizletandroid.ui.library.data.p item = (com.quizlet.quizletandroid.ui.library.data.p) obj;
                Intrinsics.checkNotNullParameter(item, "p0");
                c0 c0Var8 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var8.getClass();
                Intrinsics.checkNotNullParameter(item, "item");
                boolean z2 = item instanceof C4656j;
                if (z2 || (item instanceof C4658l) || (item instanceof com.quizlet.quizletandroid.ui.library.data.o)) {
                    z = true;
                } else if (item instanceof C4657k) {
                    z = ((C4657k) item).b instanceof L;
                } else if (item instanceof C4659m) {
                    z = ((C4659m) item).b instanceof com.quizlet.library.data.b;
                } else {
                    if (!(item instanceof com.quizlet.quizletandroid.ui.library.data.n)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    z = ((com.quizlet.quizletandroid.ui.library.data.n) item).b instanceof com.quizlet.library.viewmodels.t;
                }
                if (z) {
                    Long lD = c0.D(item);
                    if (z2) {
                        com.quizlet.library.viewmodels.a aVar3 = ((C4656j) item).b;
                        if (aVar3 instanceof com.quizlet.library.viewmodels.b) {
                            i = 16;
                        } else if (aVar3 instanceof com.quizlet.library.viewmodels.v) {
                            i = 15;
                        } else {
                            if (!(aVar3 instanceof com.quizlet.library.viewmodels.w)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            i = 14;
                        }
                    } else if (item instanceof C4657k) {
                        i = 1;
                    } else if (item instanceof C4658l) {
                        i = 3;
                    } else if (item instanceof C4659m) {
                        i = 20;
                    } else if (item instanceof com.quizlet.quizletandroid.ui.library.data.n) {
                        i = 29;
                    } else {
                        if (!(item instanceof com.quizlet.quizletandroid.ui.library.data.o)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        i = 4;
                    }
                    EnumC4525u1 enumC4525u1 = EnumC4525u1.YOUR_LIBRARY;
                    if (z2) {
                        w1Var = w1.YOUR_LIBRARY_EXPLANATIONS;
                    } else if (item instanceof C4657k) {
                        w1Var = w1.YOUR_LIBRARY_SETS;
                    } else if (item instanceof C4658l) {
                        w1Var = w1.YOUR_LIBRARY_FOLDERS;
                    } else if (item instanceof C4659m) {
                        w1Var = w1.YOUR_LIBRARY_MAGIC_NOTES;
                    } else if (item instanceof com.quizlet.quizletandroid.ui.library.data.n) {
                        w1Var = w1.YOUR_LIBRARY_PRACTICE_TESTS;
                    } else {
                        if (!(item instanceof com.quizlet.quizletandroid.ui.library.data.o)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        w1Var = w1.YOUR_LIBRARY_CLASSES;
                    }
                    w1 w1Var2 = w1Var;
                    int iA = item.a();
                    if ((item instanceof C4657k) || (item instanceof C4658l) || (item instanceof com.quizlet.quizletandroid.ui.library.data.o)) {
                        Long lD2 = c0.D(item);
                        if (lD2 != null) {
                            string = lD2.toString();
                        }
                    } else if (item instanceof C4656j) {
                        com.quizlet.library.viewmodels.a aVar4 = ((C4656j) item).b;
                        if (aVar4 instanceof com.quizlet.library.viewmodels.b) {
                            string = ((com.quizlet.library.viewmodels.b) aVar4).a.a;
                        } else if (aVar4 instanceof com.quizlet.library.viewmodels.v) {
                            string = ((com.quizlet.library.viewmodels.v) aVar4).a.a;
                        } else {
                            if (!(aVar4 instanceof com.quizlet.library.viewmodels.w)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            string = ((com.quizlet.library.viewmodels.w) aVar4).a.a;
                        }
                    } else if (item instanceof C4659m) {
                        com.quizlet.library.data.d dVar = ((C4659m) item).b;
                        com.quizlet.library.data.b bVar7 = dVar instanceof com.quizlet.library.data.b ? (com.quizlet.library.data.b) dVar : null;
                        if (bVar7 != null) {
                            string = bVar7.b.a;
                        }
                    } else {
                        if (!(item instanceof com.quizlet.quizletandroid.ui.library.data.n)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        com.quizlet.library.viewmodels.e eVar = ((com.quizlet.quizletandroid.ui.library.data.n) item).b;
                        com.quizlet.library.viewmodels.t tVar = eVar instanceof com.quizlet.library.viewmodels.t ? (com.quizlet.library.viewmodels.t) eVar : null;
                        if (tVar != null) {
                            string = tVar.b.a;
                        }
                    }
                    AbstractC3514p4.a(c0Var8.r, lD, i, enumC4525u1, w1Var2, 0, iA, null, string, null, null, null, 1856);
                }
                return Unit.a;
            case 12:
                int iIntValue2 = ((Number) obj).intValue();
                c0 c0Var9 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var9.getClass();
                Y1 y1 = (Y1) Y1.f.get(iIntValue2);
                c0Var9.w = y1;
                int iOrdinal2 = y1.ordinal();
                com.quizlet.library.logging.b bVar8 = c0Var9.i;
                if (iOrdinal2 == 0) {
                    bVar8.getClass();
                    bVar8.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_tabs_all_sets", null, 14));
                } else if (iOrdinal2 == 1) {
                    bVar8.getClass();
                    bVar8.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_tabs_sets_created", null, 14));
                } else if (iOrdinal2 == 2) {
                    bVar8.getClass();
                    bVar8.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_tabs_studied_sets", null, 14));
                } else {
                    if (iOrdinal2 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    bVar8.getClass();
                    bVar8.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_tabs_downloaded_sets", null, 14));
                }
                c0Var9.B();
                return Unit.a;
            case 13:
                String query = (String) obj;
                Intrinsics.checkNotNullParameter(query, "p0");
                c0 c0Var10 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var10.getClass();
                Intrinsics.checkNotNullParameter(query, "query");
                c0Var10.x = query;
                com.quizlet.library.logging.b bVar9 = c0Var10.i;
                bVar9.getClass();
                Intrinsics.checkNotNullParameter(query, "query");
                bVar9.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_filter", new com.quizlet.features.notes.logging.c(query, 29), 6));
                c0Var10.B();
                return Unit.a;
            case 14:
                long jLongValue2 = ((Number) obj).longValue();
                c0 c0Var11 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar10 = c0Var11.i;
                bVar10.getClass();
                bVar10.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_card", new com.braze.requests.framework.m(23, jLongValue2), 6));
                c0Var11.C(1, String.valueOf(jLongValue2));
                E.A(p0.j(c0Var11), null, null, new com.quizlet.quizletandroid.ui.library.Y(c0Var11, jLongValue2, null), 3);
                return Unit.a;
            case 15:
                long jLongValue3 = ((Number) obj).longValue();
                c0 c0Var12 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar11 = c0Var12.i;
                bVar11.getClass();
                bVar11.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_card", new com.braze.requests.framework.m(21, jLongValue3), 6));
                c0Var12.C(3, String.valueOf(jLongValue3));
                E.A(p0.j(c0Var12), null, null, new P(c0Var12, jLongValue3, null), 3);
                return Unit.a;
            case 16:
                long jLongValue4 = ((Number) obj).longValue();
                c0 c0Var13 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar12 = c0Var13.i;
                bVar12.getClass();
                bVar12.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_library_card", new com.braze.requests.framework.m(22, jLongValue4), 6));
                c0Var13.C(4, String.valueOf(jLongValue4));
                E.A(p0.j(c0Var13), null, null, new M(c0Var13, jLongValue4, null), 3);
                return Unit.a;
            case 17:
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "p0");
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                fVar.getClass();
                Intrinsics.checkNotNullParameter(email, "email");
                if (email.length() == 0) {
                    do {
                        s0Var = fVar.h;
                        value = s0Var.getValue();
                    } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value, aVar, null, 2)));
                } else {
                    fVar.e.getClass();
                    if (com.quizlet.qutils.string.c.c(email)) {
                        fVar.j.dispose();
                        androidx.work.impl.model.v vVar = fVar.d;
                        vVar.getClass();
                        Intrinsics.checkNotNullParameter(email, "email");
                        io.reactivex.rxjava3.subjects.r stopToken = fVar.c;
                        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                        io.reactivex.rxjava3.internal.operators.single.k kVarH = ((androidx.work.impl.model.c) vVar.c).c(stopToken, new com.braze.triggers.managers.h(26, vVar, email)).l(fVar.f).h(fVar.g);
                        Intrinsics.checkNotNullExpressionValue(kVarH, "observeOn(...)");
                        io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(kVarH, new s(1, fVar, com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onCheckEmailError", "onCheckEmailError(Ljava/lang/Throwable;)V", 0, 20), new s(1, fVar, com.quizlet.quizletandroid.ui.login.viewmodels.f.class, "onCheckEmailSuccess", "onCheckEmailSuccess(Lcom/quizlet/data/model/CheckEmail;)V", 0, 21));
                        fVar.j = eVarB;
                        fVar.A(eVarB);
                    } else {
                        Intrinsics.checkNotNullParameter(email, "email");
                        if (Pattern.compile("[a-zA-Z0-9\\+\\.\\_\\%\\-\\+]{1,256}\\@.*").matcher(email).matches()) {
                            fVar.B(R.string.invalid_email_address);
                        }
                    }
                }
                return Unit.a;
            case 18:
                String password = (String) obj;
                Intrinsics.checkNotNullParameter(password, "p0");
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar2 = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                fVar2.getClass();
                Intrinsics.checkNotNullParameter(password, "password");
                int length = password.length();
                s0 s0Var4 = fVar2.h;
                if (length == 0) {
                    do {
                        value3 = s0Var4.getValue();
                    } while (!s0Var4.k(value3, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value3, null, aVar, 1)));
                } else {
                    do {
                        value2 = s0Var4.getValue();
                    } while (!s0Var4.k(value2, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value2, null, cVar, 1)));
                }
                return Unit.a;
            case 19:
                com.quizlet.login.signupwall.a p03 = (com.quizlet.login.signupwall.a) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                SignUpWallModalFragment signUpWallModalFragment = (SignUpWallModalFragment) this.receiver;
                String str2 = SignUpWallModalFragment.X;
                signUpWallModalFragment.getClass();
                int iOrdinal3 = p03.ordinal();
                kotlin.u uVar = signUpWallModalFragment.M;
                if (iOrdinal3 != 0) {
                    if (iOrdinal3 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    com.quizlet.local.ormlite.models.term.b bVar13 = signUpWallModalFragment.J;
                    if (bVar13 == null) {
                        Intrinsics.m("navigationManager");
                        throw null;
                    }
                    Context context = signUpWallModalFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                    Intent intent = (Intent) uVar.getValue();
                    Intrinsics.checkNotNullParameter(context, "context");
                    Intent intent2 = (Intent) ((com.quizlet.quizletandroid.t) bVar13.b).get();
                    if (intent != null) {
                        androidx.core.app.W w = new androidx.core.app.W(context);
                        w.a(intent);
                        w.a.add(intent2);
                        w.e();
                    } else {
                        intent2.setAction("open_start_activity");
                        context.startActivity(intent2);
                    }
                } else {
                    if (signUpWallModalFragment.J == null) {
                        Intrinsics.m("navigationManager");
                        throw null;
                    }
                    Context context2 = signUpWallModalFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context2, "requireContext(...)");
                    Intent intent3 = (Intent) uVar.getValue();
                    Intrinsics.checkNotNullParameter(context2, "context");
                    boolean z3 = intent3 != null;
                    String str3 = LoginNavActivity.i;
                    Intent intentC = B.c(context2, z3);
                    if (intent3 != null) {
                        androidx.core.app.W w2 = new androidx.core.app.W(context2);
                        w2.a(intent3);
                        w2.a.add(intentC);
                        w2.e();
                    } else {
                        intentC.setAction("open_start_activity");
                        context2.startActivity(intentC);
                    }
                }
                return Unit.a;
            case 20:
                Throwable p04 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar3 = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                fVar3.getClass();
                timber.log.c.a.g(AbstractC0147y.d("Failed to validate during a validate email network request. ", p04.getMessage()), new Object[0]);
                fVar3.B(R.string.no_network_connection_error_msg);
                return Unit.a;
            case 21:
                com.quizlet.data.model.B p05 = (com.quizlet.data.model.B) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar4 = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                fVar4.getClass();
                if (p05.b) {
                    fVar4.B(R.string.account_already_exists);
                } else if (p05.a) {
                    do {
                        s0Var2 = fVar4.h;
                        value4 = s0Var2.getValue();
                    } while (!s0Var2.k(value4, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value4, cVar, null, 2)));
                } else {
                    fVar4.B(R.string.invalid_email_address);
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.f p06 = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.f) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                EditSetFragment editSetFragment = (EditSetFragment) this.receiver;
                String str4 = EditSetFragment.J;
                editSetFragment.getClass();
                int iOrdinal4 = p06.ordinal();
                if (iOrdinal4 == 0) {
                    editSetFragment.b0().setIsLocked(false);
                } else {
                    if (iOrdinal4 != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    editSetFragment.b0().setIsLocked(true);
                }
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                org.wordpress.aztec.toolbar.c richTextOption = (org.wordpress.aztec.toolbar.c) obj;
                Intrinsics.checkNotNullParameter(richTextOption, "p0");
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVar2 = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.e) this.receiver;
                eVar2.getClass();
                Intrinsics.checkNotNullParameter(richTextOption, "richTextOption");
                io.reactivex.rxjava3.internal.observers.e eVarI = eVar2.c.k(eVar2.d).i(new com.quizlet.billing.manager.b(i2, eVar2, richTextOption), io.reactivex.rxjava3.internal.functions.d.e);
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                Intrinsics.checkNotNullParameter(eVarI, "<this>");
                eVar2.A(eVarI);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                ((timber.log.a) this.receiver).h((Throwable) obj);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                List data = (List) obj;
                Intrinsics.checkNotNullParameter(data, "p0");
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.a aVar5 = ((com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.receiver).v;
                aVar5.getClass();
                Intrinsics.checkNotNullParameter(data, "data");
                EventLoggerExt.a(aVar5.a, "get_started_home_section_impression", new com.quizlet.features.setpage.header.ui.g(24, data, aVar5));
                return Unit.a;
            case EventType.CDN /* 26 */:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 27:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 28:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                ((com.quizlet.features.questiontypes.basequestion.k) this.receiver).h.j(bool);
                return Unit.a;
            default:
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f p07 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.f) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.i) ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b) this.receiver)).E(p07);
                return Unit.a;
        }
    }
}
