package com.quizlet.infra.legacysyncengine.tasks.parse;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.Size;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Toast;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.z0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1126c0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.fragment.app.m0;
import androidx.recyclerview.widget.RecyclerView;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4604h;
import com.quizlet.quizletandroid.databinding.C4607k;
import com.quizlet.quizletandroid.databinding.C4609m;
import com.quizlet.quizletandroid.databinding.C4619x;
import com.quizlet.quizletandroid.databinding.D;
import com.quizlet.quizletandroid.ui.common.views.ToggleSwipeableViewPager;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.library.LibraryFragment;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.o;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.fragments.k;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import com.quizlet.studiablemodels.diagrams.DiagramDataKt;
import com.quizlet.ui.webview.QuizletWebView;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.l;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jsoup.select.n;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.functions.i, io.reactivex.rxjava3.functions.e, m0, com.quizlet.uicommon.ui.common.dialogs.f, com.quizlet.qutils.rx.c, com.quizlet.quizletandroid.ui.common.widgets.a, InterfaceC1062t, io.reactivex.rxjava3.core.j, n {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.quizlet.qutils.rx.c
    public void accept(Object obj) throws Exception {
        Object obj2 = this.b;
        switch (this.a) {
            case 6:
                Intent intent = (Intent) obj;
                String str = ClassContentListFragment.n;
                Intrinsics.checkNotNullParameter(intent, "intent");
                ((ClassContentListFragment) obj2).startActivityForResult(intent, 201);
                break;
            case 11:
                ((UserSetListFragment) obj2).startActivityForResult((Intent) obj, 201);
                break;
            case 16:
                String str2 = (String) obj;
                Object obj3 = ((com.quizlet.quizletandroid.ui.setcreation.adapters.c) obj2).d.get();
                Intrinsics.d(obj3);
                EditSetLanguageSelectionActivity editSetLanguageSelectionActivity = (EditSetLanguageSelectionActivity) ((com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.c) obj3);
                com.bumptech.glide.c.C(editSetLanguageSelectionActivity.u, false);
                if (!str2.equals(editSetLanguageSelectionActivity.s)) {
                    Intent intent2 = new Intent();
                    intent2.putExtra("editSetLanguageCodeResult", str2);
                    editSetLanguageSelectionActivity.setResult(4321, intent2);
                    editSetLanguageSelectionActivity.finish();
                    break;
                } else {
                    editSetLanguageSelectionActivity.setResult(1234);
                    editSetLanguageSelectionActivity.finish();
                    break;
                }
            default:
                Drawable drawable = (Drawable) obj;
                String str3 = ImageOverlayDialogFragment.x;
                ImageOverlayDialogFragment imageOverlayDialogFragment = (ImageOverlayDialogFragment) obj2;
                if (imageOverlayDialogFragment.isAdded()) {
                    WindowManager windowManager = imageOverlayDialogFragment.requireActivity().getWindowManager();
                    Intrinsics.checkNotNullExpressionValue(windowManager, "getWindowManager(...)");
                    Size sizeB = AbstractC3206m6.b(windowManager);
                    int intrinsicWidth = drawable.getIntrinsicWidth();
                    int intrinsicHeight = drawable.getIntrinsicHeight();
                    int width = sizeB.getWidth();
                    int height = sizeB.getHeight();
                    int iFloor = intrinsicWidth * 2;
                    int iFloor2 = intrinsicHeight * 2;
                    if (imageOverlayDialogFragment.getResources().getConfiguration().orientation == 1) {
                        height = (height * 2) / 3;
                    } else {
                        width = (width * 2) / 3;
                    }
                    if (iFloor2 > height) {
                        float f = height / iFloor2;
                        iFloor2 = (int) Math.floor(r8 * f);
                        iFloor = (int) Math.floor(iFloor * f);
                    }
                    if (iFloor > width) {
                        float f2 = width / iFloor;
                        iFloor2 = (int) Math.floor(iFloor2 * f2);
                        iFloor = (int) Math.floor(r1 * f2);
                    }
                    ViewGroup.LayoutParams layoutParams = imageOverlayDialogFragment.R().getLayoutParams();
                    layoutParams.width = iFloor;
                    layoutParams.height = iFloor2;
                    imageOverlayDialogFragment.R().setScaleType(ImageView.ScaleType.FIT_CENTER);
                    Bundle arguments = imageOverlayDialogFragment.getArguments();
                    if (arguments != null) {
                        int i = arguments.getInt("overlayTintColor");
                        Integer numValueOf = Integer.valueOf(i);
                        if (i == 0) {
                            numValueOf = null;
                        }
                        if (numValueOf != null) {
                            imageOverlayDialogFragment.R().setColorFilter(numValueOf.intValue());
                            break;
                        }
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                androidx.core.util.c cVar = (androidx.core.util.c) this.b;
                return new e((ModelType) obj, (ApiResponse) cVar.a, ((Integer) cVar.b).intValue());
            default:
                DBStudySet dBStudySet = (DBStudySet) obj;
                ((com.quizlet.quizletandroid.ui.setcreation.managers.i) this.b).getClass();
                if (dBStudySet.getId() <= 0 || !dBStudySet.getIsCreated()) {
                    long seconds = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis());
                    if (dBStudySet.getId() <= 0) {
                        dBStudySet.setReadyToCreate(true);
                    } else {
                        dBStudySet.setPublishedTimestamp(Long.valueOf(seconds));
                    }
                    dBStudySet.setTimestamp((int) seconds);
                }
                return dBStudySet;
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        ArrayList arrayList;
        int i2 = 2;
        List listUnmodifiableList = null;
        listUnmodifiableList = null;
        Object obj = this.b;
        switch (this.a) {
            case 5:
                String str = GroupFragment.M;
                eVar.dismiss();
                GroupFragment groupFragment = (GroupFragment) obj;
                DBGroupMembership dBGroupMembership = groupFragment.H;
                Intrinsics.d(dBGroupMembership);
                dBGroupMembership.setDeleted(true);
                com.quizlet.infra.legacysyncengine.net.f fVar = groupFragment.o;
                if (fVar == null) {
                    Intrinsics.m("syncDispatcher");
                    throw null;
                }
                fVar.a(groupFragment.H);
                groupFragment.H = null;
                Toast.makeText(groupFragment.requireContext(), groupFragment.getString(R.string.class_dropped), 0).show();
                groupFragment.requireActivity().finish();
                return;
            case 8:
                int i3 = QuizletLiveActivity.z;
                ((QuizletLiveActivity) obj).finish();
                eVar.dismiss();
                return;
            case 13:
                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar = (com.quizlet.quizletandroid.ui.setcreation.activities.d) obj;
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = dVar.y;
                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = dVar.B.A;
                if (fVar2 != null && (arrayList = fVar2.p) != null) {
                    listUnmodifiableList = Collections.unmodifiableList(arrayList);
                }
                iVar.o.i(new com.quizlet.infra.legacysyncengine.net.request.e(iVar, listUnmodifiableList, dVar.p, i2), new com.quizlet.billing.subscriptions.c(2));
                eVar.dismiss();
                return;
            case 14:
                com.quizlet.quizletandroid.ui.setcreation.activities.h hVar = (com.quizlet.quizletandroid.ui.setcreation.activities.h) obj;
                eVar.dismiss();
                if (i != 1) {
                    return;
                }
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = hVar.p;
                iVar2.o.i(new com.quizlet.infra.legacysyncengine.net.request.e(iVar2, hVar.s, hVar.m, i2), new com.quizlet.billing.subscriptions.c(2));
                return;
            case 15:
                eVar.dismiss();
                o oVar = (o) obj;
                oVar.b.invoke(((com.quizlet.quizletandroid.ui.setcreation.activities.n) oVar.c.get(oVar.getAdapterPosition())).b, Boolean.valueOf(i == 1));
                return;
            case 17:
                com.quizlet.quizletandroid.ui.setcreation.dialogs.a aVar = (com.quizlet.quizletandroid.ui.setcreation.dialogs.a) obj;
                QFormField qFormField = aVar.r;
                if (qFormField == null) {
                    Intrinsics.m("titleField");
                    throw null;
                }
                if (StringsKt.g0(String.valueOf(qFormField.getText())).toString().length() <= 0) {
                    QFormField qFormField2 = aVar.r;
                    if (qFormField2 == null) {
                        Intrinsics.m("titleField");
                        throw null;
                    }
                    Context context = aVar.getContext();
                    qFormField2.setError(context != null ? context.getString(R.string.title_cannot_be_empty_message) : null);
                    return;
                }
                eVar.dismiss();
                QFormField qFormField3 = aVar.r;
                if (qFormField3 == null) {
                    Intrinsics.m("titleField");
                    throw null;
                }
                com.bumptech.glide.c.C(qFormField3, false);
                k kVar = aVar.q;
                if (kVar != null) {
                    QFormField qFormField4 = aVar.r;
                    if (qFormField4 != null) {
                        kVar.invoke(StringsKt.g0(String.valueOf(qFormField4.getText())).toString());
                        return;
                    } else {
                        Intrinsics.m("titleField");
                        throw null;
                    }
                }
                return;
            case EventType.SUBS /* 25 */:
                l lVar = (l) obj;
                Fragment targetFragment = lVar.getTargetFragment();
                if (targetFragment != null) {
                    targetFragment.onActivityResult(lVar.getTargetRequestCode(), -1, null);
                }
                eVar.dismiss();
                return;
            default:
                I activity = ((com.quizlet.upgrade.ui.fragment.a) obj).getActivity();
                if (activity != null) {
                    activity.finish();
                    return;
                }
                return;
        }
    }

    @Override // org.jsoup.select.n
    public void d(org.jsoup.nodes.n nVar, int i) {
        org.jsoup.nodes.i.E(nVar, (StringBuilder) this.b);
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        List list = (List) obj2;
        int i = DiagramOverviewActivity.o1;
        DiagramData.Builder builder = new DiagramData.Builder();
        builder.d(((DBStudySet) obj3).getId());
        DBImage image = ((DBImageRef) obj).getImage();
        Intrinsics.checkNotNullExpressionValue(image, "getImage(...)");
        builder.c(image);
        Intrinsics.d(list);
        builder.b(DiagramDataKt.a(list, A.b((DBTerm) this.b)));
        return builder.a();
    }

    @Override // io.reactivex.rxjava3.core.j
    public void l(C4899s emitter) {
        Intrinsics.checkNotNullParameter(emitter, "emitter");
        final View viewFindViewById = ((I) this.b).findViewById(android.R.id.content);
        final com.google.firebase.perf.util.a aVar = new com.google.firebase.perf.util.a(viewFindViewById, emitter);
        viewFindViewById.getViewTreeObserver().addOnGlobalLayoutListener(aVar);
        emitter.d(new io.reactivex.rxjava3.functions.c() { // from class: com.quizlet.qutils.android.c
            @Override // io.reactivex.rxjava3.functions.c
            public final void cancel() {
                viewFindViewById.getViewTreeObserver().removeOnGlobalLayoutListener(aVar);
            }
        });
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        ((com.quizlet.infra.legacysyncengine.tasks.read.sync.a) this.b).getClass();
        DBStudySet set = ((DBSession) ((DBModel) obj)).getSet();
        return (set == null || set.getDeleted() || set.getPublishedTimestamp() <= 0 || set.getDirty()) ? false : true;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        Object obj = this.b;
        switch (this.a) {
            case 10:
                String str = ProfileFragment.x;
                androidx.core.graphics.e eVarG = d0.a.g(647);
                Intrinsics.d(view);
                view.setPadding(eVarG.a, view.getPaddingTop(), eVarG.c, view.getPaddingBottom());
                ToggleSwipeableViewPager profileViewPager = ((D) ((ProfileFragment) obj).J()).e;
                Intrinsics.checkNotNullExpressionValue(profileViewPager, "profileViewPager");
                profileViewPager.setPadding(profileViewPager.getPaddingLeft(), profileViewPager.getPaddingTop(), profileViewPager.getPaddingRight(), eVarG.d);
                return D0.b;
            case 18:
                String str2 = EditSetFragment.J;
                z0 z0Var = d0.a;
                androidx.core.graphics.e eVarG2 = z0Var.g(647);
                androidx.core.graphics.e eVarG3 = z0Var.g(8);
                Intrinsics.d(view);
                ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                if (layoutParams == null) {
                    throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                }
                ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
                marginLayoutParams.bottomMargin = eVarG3.d;
                view.setLayoutParams(marginLayoutParams);
                RecyclerView editSetTermList = ((C4619x) ((EditSetFragment) obj).J()).b;
                Intrinsics.checkNotNullExpressionValue(editSetTermList, "editSetTermList");
                editSetTermList.setPadding(editSetTermList.getPaddingLeft(), editSetTermList.getPaddingTop(), editSetTermList.getPaddingRight(), eVarG2.d);
                return D0.b;
            case 20:
                String str3 = LearningAssistantActivity.D;
                androidx.core.graphics.e eVarG4 = d0.a.g(647);
                LinearLayout learnLinearLayout = ((C4609m) ((LearningAssistantActivity) obj).K()).d;
                Intrinsics.checkNotNullExpressionValue(learnLinearLayout, "learnLinearLayout");
                learnLinearLayout.setPadding(eVarG4.a, eVarG4.b, eVarG4.c, eVarG4.d);
                return D0.b;
            case 21:
                String str4 = MatchActivity.s;
                androidx.core.graphics.e eVarG5 = d0.a.g(647);
                MatchActivity matchActivity = (MatchActivity) obj;
                FrameLayout frameLayout = ((C4604h) matchActivity.K()).c;
                Intrinsics.checkNotNullExpressionValue(frameLayout, "frameLayout");
                frameLayout.setPadding(frameLayout.getPaddingLeft(), eVarG5.b, frameLayout.getPaddingRight(), frameLayout.getPaddingBottom());
                Toolbar toolbar = (Toolbar) ((C4604h) matchActivity.K()).b.d;
                Intrinsics.checkNotNullExpressionValue(toolbar, "toolbar");
                int paddingTop = toolbar.getPaddingTop();
                int paddingBottom = toolbar.getPaddingBottom();
                int i = eVarG5.a;
                int i2 = eVarG5.c;
                toolbar.setPadding(i, paddingTop, i2, paddingBottom);
                FrameLayout frameLayout2 = (FrameLayout) ((C4604h) matchActivity.K()).e.b;
                Intrinsics.checkNotNullExpressionValue(frameLayout2, "getRoot(...)");
                frameLayout2.setPadding(i, frameLayout2.getPaddingTop(), i2, frameLayout2.getPaddingBottom());
                Intrinsics.d(view);
                view.setPadding(i, view.getPaddingTop(), i2, eVarG5.d);
                return D0.b;
            default:
                String str5 = WebViewActivity.u;
                androidx.core.graphics.e eVarG6 = d0.a.g(647);
                WebViewActivity webViewActivity = (WebViewActivity) obj;
                AppBarLayout appBarLayout = ((C4607k) webViewActivity.K()).b;
                Intrinsics.checkNotNullExpressionValue(appBarLayout, "appBarLayout");
                appBarLayout.setPadding(appBarLayout.getPaddingLeft(), eVarG6.b, appBarLayout.getPaddingRight(), appBarLayout.getPaddingBottom());
                Toolbar toolbar2 = ((C4607k) webViewActivity.K()).e;
                Intrinsics.checkNotNullExpressionValue(toolbar2, "toolbar");
                int paddingTop2 = toolbar2.getPaddingTop();
                int paddingBottom2 = toolbar2.getPaddingBottom();
                int i3 = eVarG6.a;
                int i4 = eVarG6.c;
                toolbar2.setPadding(i3, paddingTop2, i4, paddingBottom2);
                QuizletWebView webView = ((C4607k) webViewActivity.K()).f;
                Intrinsics.checkNotNullExpressionValue(webView, "webView");
                ViewGroup.LayoutParams layoutParams2 = webView.getLayoutParams();
                if (layoutParams2 == null) {
                    throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                }
                ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) layoutParams2;
                marginLayoutParams2.leftMargin = i3;
                marginLayoutParams2.rightMargin = i4;
                webView.setLayoutParams(marginLayoutParams2);
                Intrinsics.d(view);
                view.setPadding(view.getPaddingLeft(), view.getPaddingTop(), view.getPaddingRight(), eVarG6.d);
                return D0.b;
        }
    }

    @Override // androidx.fragment.app.m0
    public void y(Bundle result, String requestKey) {
        Object obj = this.b;
        switch (this.a) {
            case 4:
                Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                Intrinsics.checkNotNullParameter(result, "result");
                if (requestKey.hashCode() == -1072223878 && requestKey.equals("createFolderRequestKey")) {
                    ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) obj).v(result.getLong("createFolderResultArgFolderId"));
                    break;
                }
                break;
            default:
                String str = LibraryFragment.n;
                Intrinsics.checkNotNullParameter(requestKey, "<unused var>");
                Intrinsics.checkNotNullParameter(result, "result");
                long j = result.getLong("createFolderResultArgFolderId");
                LibraryFragment libraryFragment = (LibraryFragment) obj;
                String str2 = FolderActivity.j;
                Context contextRequireContext = libraryFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                libraryFragment.startActivity(AbstractC3309z0.b(contextRequireContext, j));
                C1126c0 c1126c0 = (C1126c0) libraryFragment.getParentFragmentManager().n.remove("createFolderRequestKey");
                if (c1126c0 != null) {
                    c1126c0.a.b(c1126c0.c);
                }
                AbstractC1136h0.N(2);
                break;
        }
    }
}
