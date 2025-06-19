package androidx.paging;

import android.content.Context;
import android.content.Intent;
import androidx.camera.camera2.internal.C0128e;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_camera.L1;
import com.google.android.gms.internal.mlkit_vision_common.M3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.quizlet.data.model.m2;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import com.quizlet.features.practicetest.PracticeTestActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import com.quizlet.quizletandroid.ui.classcreation.ClassCreationActivity;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import kotlin.InterfaceC4938g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.C4942a;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final /* synthetic */ class S implements InterfaceC5002j, InterfaceC4953l {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ S(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) {
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                Object objS = ((a1) obj2).a.s((C1351y0) obj, hVar);
                return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
            case 1:
                com.quizlet.quizletandroid.ui.classcreation.data.e eVar = (com.quizlet.quizletandroid.ui.classcreation.data.e) obj;
                int i = ClassCreationActivity.j;
                ClassCreationActivity classCreationActivity = (ClassCreationActivity) obj2;
                if (eVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.c) {
                    classCreationActivity.finish();
                } else {
                    if (!(eVar instanceof com.quizlet.quizletandroid.ui.classcreation.data.d)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    long j = ((com.quizlet.quizletandroid.ui.classcreation.data.d) eVar).a;
                    classCreationActivity.finish();
                    String str = GroupActivity.u;
                    classCreationActivity.startActivity(com.quizlet.quizletandroid.ui.group.f.a(classCreationActivity, Long.valueOf(j), null, false, null));
                }
                Unit unit = Unit.a;
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                return unit;
            default:
                com.quizlet.quizletandroid.ui.library.data.F f = (com.quizlet.quizletandroid.ui.library.data.F) obj;
                String str2 = LibraryFragment.n;
                LibraryFragment libraryFragment = (LibraryFragment) obj2;
                if (f instanceof com.quizlet.quizletandroid.ui.library.data.q) {
                    long j2 = ((com.quizlet.quizletandroid.ui.library.data.q) f).a;
                    String str3 = GroupActivity.u;
                    Context contextRequireContext = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    libraryFragment.startActivity(com.quizlet.quizletandroid.ui.group.f.a(contextRequireContext, Long.valueOf(j2), null, false, null));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.t) {
                    long j3 = ((com.quizlet.quizletandroid.ui.library.data.t) f).a;
                    String str4 = FolderActivity.j;
                    Context contextRequireContext2 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    libraryFragment.startActivity(AbstractC3309z0.b(contextRequireContext2, j3));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.B) {
                    long j4 = ((com.quizlet.quizletandroid.ui.library.data.B) f).a;
                    com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                    Context contextRequireContext3 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    libraryFragment.startActivity(com.quizlet.features.setpage.e.b(eVar2, contextRequireContext3, j4, null, null, null, null, false, null, 252));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.r) {
                    long j5 = ((com.quizlet.quizletandroid.ui.library.data.r) f).a;
                    Context contextRequireContext4 = libraryFragment.requireContext();
                    int i2 = EditSetActivity.M;
                    Intent intent = new Intent(contextRequireContext4, (Class<?>) EditSetActivity.class);
                    intent.putExtra("isFromHome", false);
                    intent.putExtra("editSetActivityId", j5);
                    libraryFragment.startActivity(intent);
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.z) {
                    com.quizlet.quizletandroid.ui.library.data.z zVar = (com.quizlet.quizletandroid.ui.library.data.z) f;
                    long j6 = zVar.a;
                    com.quizlet.offline.managers.b bVar = libraryFragment.j;
                    if (bVar == null) {
                        Intrinsics.m("offlineStateManager");
                        throw null;
                    }
                    Context contextRequireContext5 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                    com.quizlet.features.setpage.e eVar3 = SetPageActivity.h1;
                    Context contextRequireContext6 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext6, "requireContext(...)");
                    ((com.quizlet.offline.managers.i) bVar).d(contextRequireContext5, zVar.b, com.quizlet.features.setpage.e.b(eVar3, contextRequireContext6, j6, null, null, null, null, false, null, 252), new C0128e(libraryFragment, j6, 2));
                } else if (Intrinsics.b(f, com.quizlet.quizletandroid.ui.library.data.v.a)) {
                    int i3 = ClassCreationActivity.j;
                    Context context = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                    Intrinsics.checkNotNullParameter(context, "context");
                    libraryFragment.startActivity(new Intent(context, (Class<?>) ClassCreationActivity.class));
                } else if (Intrinsics.b(f, com.quizlet.quizletandroid.ui.library.data.w.a)) {
                    AbstractC1136h0 parentFragmentManager = libraryFragment.getParentFragmentManager();
                    String str5 = CreateFolderModalFragment.w;
                    if (parentFragmentManager.E(str5) == null) {
                        libraryFragment.getParentFragmentManager().h0("createFolderRequestKey", libraryFragment, new com.quizlet.infra.legacysyncengine.tasks.parse.b(libraryFragment, 7));
                        new CreateFolderModalFragment().O(libraryFragment.getParentFragmentManager(), str5);
                    }
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.u) {
                    String str6 = ((com.quizlet.quizletandroid.ui.library.data.u) f).a;
                    int i4 = MagicNotesDetailActivity.i;
                    Context contextRequireContext7 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext7, "requireContext(...)");
                    libraryFragment.startActivity(assistantMode.utils.studiableMetadata.b.J(contextRequireContext7, str6, false, null));
                } else if (Intrinsics.b(f, com.quizlet.quizletandroid.ui.library.data.x.a)) {
                    int i5 = UploadNotesActivity.i;
                    Context contextRequireContext8 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext8, "requireContext(...)");
                    libraryFragment.startActivity(com.google.android.gms.internal.mlkit_common.u.i(contextRequireContext8, m2.a, null, null, null, 28));
                } else if (Intrinsics.b(f, com.quizlet.quizletandroid.ui.library.data.E.a)) {
                    int i6 = UploadNotesActivity.i;
                    Context contextRequireContext9 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext9, "requireContext(...)");
                    libraryFragment.startActivity(com.google.android.gms.internal.mlkit_common.u.i(contextRequireContext9, m2.b, null, null, null, 28));
                } else if (Intrinsics.b(f, com.quizlet.quizletandroid.ui.library.data.y.a)) {
                    int i7 = UniversalUploadFlowActivity.h;
                    Context contextRequireContext10 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext10, "requireContext(...)");
                    libraryFragment.startActivity(M3.a(contextRequireContext10, m2.c));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.A) {
                    String str7 = ((com.quizlet.quizletandroid.ui.library.data.A) f).a;
                    int i8 = PracticeTestActivity.h;
                    Context contextRequireContext11 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext11, "requireContext(...)");
                    libraryFragment.startActivity(L1.c(contextRequireContext11, str7));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.C) {
                    String isbn = ((com.quizlet.quizletandroid.ui.library.data.C) f).a;
                    com.quizlet.explanations.navigation.b bVarU = libraryFragment.U();
                    Context contextRequireContext12 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext12, "requireContext(...)");
                    Intrinsics.checkNotNullParameter(isbn, "isbn");
                    ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU).c(contextRequireContext12, new TextbookSetUpState.TableOfContents(isbn));
                } else if (f instanceof com.quizlet.quizletandroid.ui.library.data.D) {
                    String id = ((com.quizlet.quizletandroid.ui.library.data.D) f).a;
                    com.quizlet.explanations.navigation.b bVarU2 = libraryFragment.U();
                    Context contextRequireContext13 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext13, "requireContext(...)");
                    Intrinsics.checkNotNullParameter(id, "id");
                    ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU2).c(contextRequireContext13, new TextbookSetUpState.Exercise(id));
                } else {
                    if (!(f instanceof com.quizlet.quizletandroid.ui.library.data.s)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    String id2 = ((com.quizlet.quizletandroid.ui.library.data.s) f).a;
                    libraryFragment.U();
                    Context context2 = libraryFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(context2, "requireContext(...)");
                    Intrinsics.checkNotNullParameter(context2, "context");
                    Intrinsics.checkNotNullParameter(id2, "id");
                    String str8 = QuestionDetailActivity.t;
                    context2.startActivity(i7.a(context2, new QuestionDetailSetUpState.WithId(id2)));
                }
                Unit unit2 = Unit.a;
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                return unit2;
        }
    }

    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if ((obj instanceof InterfaceC5002j) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 1:
                if ((obj instanceof InterfaceC5002j) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            default:
                if ((obj instanceof InterfaceC5002j) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
        }
        return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        switch (this.a) {
            case 0:
                return new C4956o(2, 0, a1.class, (a1) this.b, "send", "send(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;");
            case 1:
                return new C4942a(2, 4, ClassCreationActivity.class, (ClassCreationActivity) this.b, "handleNavigation", "handleNavigation(Lcom/quizlet/quizletandroid/ui/classcreation/data/ClassCreationNavigation;)V");
            default:
                return new C4942a(2, 4, LibraryFragment.class, (LibraryFragment) this.b, "handleNavigation", "handleNavigation(Lcom/quizlet/quizletandroid/ui/library/data/LibraryNavigation;)V");
        }
    }

    public final int hashCode() {
        switch (this.a) {
        }
        return getFunctionDelegate().hashCode();
    }
}
