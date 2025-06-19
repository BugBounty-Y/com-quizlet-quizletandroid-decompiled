package com.braze.ui.inappmessage.views;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.RadioButton;
import androidx.appcompat.widget.SwitchCompat;
import androidx.camera.camera2.internal.compat.workaround.e;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.I;
import com.airbnb.lottie.animation.keyframe.q;
import com.braze.models.cards.CaptionedImageCard;
import com.braze.models.cards.ImageOnlyCard;
import com.braze.models.cards.ShortNewsCard;
import com.braze.models.cards.TextAnnouncementCard;
import com.braze.ui.widget.CaptionedImageCardView;
import com.braze.ui.widget.ImageOnlyCardView;
import com.braze.ui.widget.ShortNewsCardView;
import com.braze.ui.widget.TextAnnouncementCardView;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.google.android.material.snackbar.h;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.UI.DataModels.g;
import com.onetrust.otpublishers.headless.UI.DataModels.j;
import com.onetrust.otpublishers.headless.UI.adapter.A;
import com.onetrust.otpublishers.headless.UI.adapter.B;
import com.onetrust.otpublishers.headless.UI.adapter.C4053i;
import com.onetrust.otpublishers.headless.UI.adapter.D;
import com.onetrust.otpublishers.headless.UI.adapter.J;
import com.onetrust.otpublishers.headless.UI.adapter.L;
import com.onetrust.otpublishers.headless.UI.fragment.C4063g;
import com.onetrust.otpublishers.headless.UI.fragment.ViewOnClickListenerC4065i;
import com.onetrust.otpublishers.headless.UI.fragment.s;
import com.onetrust.otpublishers.headless.UI.viewmodel.d;
import com.onetrust.otpublishers.headless.databinding.f;
import com.quizlet.data.model.CreatedFolderWithCreator;
import com.quizlet.edgy.ui.recyclerview.adapter.i;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.SegmentedBucketLayout2;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import com.quizlet.quizletandroid.ui.profile.UserFolderListFragment;
import com.quizlet.quizletandroid.ui.profile.t;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeResultsView;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;
import com.quizlet.upgrade.data.v;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) throws Exception {
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                InAppMessageFullView.resetMessageMargins$lambda$3$lambda$2((InAppMessageFullView) obj2, (View) obj, view);
                return;
            case 1:
                ((CaptionedImageCardView) obj2).lambda$onSetCard$0((CaptionedImageCard) obj, view);
                return;
            case 2:
                ((ImageOnlyCardView) obj2).lambda$onSetCard$0((ImageOnlyCard) obj, view);
                return;
            case 3:
                ((ShortNewsCardView) obj2).lambda$onSetCard$0((ShortNewsCard) obj, view);
                return;
            case 4:
                ((TextAnnouncementCardView) obj2).lambda$onSetCard$0((TextAnnouncementCard) obj, view);
                return;
            case 5:
                h hVar = (h) obj2;
                hVar.getClass();
                ((View.OnClickListener) obj).onClick(view);
                hVar.a(1);
                return;
            case 6:
                e eVar = (e) obj2;
                ((h) obj).a(3);
                if (eVar.b) {
                    return;
                }
                eVar.b = true;
                return;
            case 7:
                e eVar2 = (e) obj2;
                ((h) obj).a(3);
                if (eVar2.b) {
                    return;
                }
                eVar2.b = true;
                return;
            case 8:
                C4053i c4053i = (C4053i) obj2;
                c4053i.getClass();
                ViewOnClickListenerC4065i viewOnClickListenerC4065i = new ViewOnClickListenerC4065i();
                Bundle bundle = new Bundle();
                bundle.putString("string", OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG);
                viewOnClickListenerC4065i.setArguments(bundle);
                viewOnClickListenerC4065i.B = c4053i.a;
                viewOnClickListenerC4065i.F = (JSONObject) obj;
                viewOnClickListenerC4065i.w = c4053i.h;
                if (viewOnClickListenerC4065i.isAdded()) {
                    return;
                }
                com.google.mlkit.common.internal.model.a.o(viewOnClickListenerC4065i, (I) c4053i.i, OTFragmentTags.OT_IAB_ILLUSTRATION_DETAILS_TAG);
                return;
            case 9:
                B b = (B) obj2;
                RadioButton radioButton = b.d;
                if (radioButton != null) {
                    radioButton.setChecked(false);
                }
                A a = (A) obj;
                a.b.setChecked(true);
                b.d = a.b;
                return;
            case 10:
                D this$0 = (D) obj2;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                this$0.e.invoke(((j) obj).a);
                return;
            case 11:
                J this$02 = (J) obj2;
                Intrinsics.checkNotNullParameter(this$02, "this$0");
                this$02.f.invoke(((j) obj).a);
                return;
            case 12:
                L this$03 = (L) obj2;
                Intrinsics.checkNotNullParameter(this$03, "this$0");
                this$03.e.invoke(((j) obj).a);
                return;
            case 13:
                com.google.firebase.heartbeatinfo.e eVar3 = C4063g.A;
                C4063g this$04 = (C4063g) obj2;
                Intrinsics.checkNotNullParameter(this$04, "this$0");
                q otBannerUIProperty = (q) obj;
                Intrinsics.checkNotNullParameter(otBannerUIProperty, "$otBannerUIProperty");
                com.onetrust.otpublishers.headless.Internal.a.c(this$04.requireContext(), (String) ((com.quizlet.data.repository.user.e) otBannerUIProperty.n).c);
                return;
            case 14:
                s this$05 = (s) obj2;
                Intrinsics.checkNotNullParameter(this$05, "this$0");
                f this_with = (f) obj;
                Intrinsics.checkNotNullParameter(this_with, "$this_with");
                boolean zIsChecked = this_with.f.isChecked();
                d dVarS = this$05.S();
                dVarS.n.clear();
                LinkedHashMap linkedHashMap = dVarS.o;
                linkedHashMap.clear();
                Object objA = AbstractC3665l4.a(dVarS.r);
                Intrinsics.checkNotNullExpressionValue(objA, "_sdkItems.requireValue()");
                Iterator it2 = ((Iterable) objA).iterator();
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    ArrayList arrayList = dVarS.n;
                    if (!zHasNext) {
                        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = dVarS.d;
                        if (oTPublishersHeadlessSDK != null) {
                            Intrinsics.checkNotNullParameter(arrayList, "<this>");
                            JSONArray jSONArray = new JSONArray();
                            Iterator it3 = arrayList.iterator();
                            while (it3.hasNext()) {
                                jSONArray.put((String) it3.next());
                            }
                            oTPublishersHeadlessSDK.updateAllSDKConsentStatus(jSONArray, zIsChecked);
                        }
                        dVarS.B();
                        return;
                    }
                    g gVar = (g) it2.next();
                    arrayList.add(gVar.a);
                    String groupId = dVarS.l.c(gVar.a);
                    if (groupId != null) {
                        Intrinsics.checkNotNullExpressionValue(groupId, "groupId");
                        linkedHashMap.put(groupId, arrayList);
                    }
                }
            case 15:
                com.google.firebase.perf.logging.b bVar = com.onetrust.otpublishers.headless.UI.fragment.D.D;
                com.onetrust.otpublishers.headless.UI.fragment.D this$06 = (com.onetrust.otpublishers.headless.UI.fragment.D) obj2;
                Intrinsics.checkNotNullParameter(this$06, "this$0");
                com.onetrust.otpublishers.headless.databinding.g this_with2 = (com.onetrust.otpublishers.headless.databinding.g) obj;
                Intrinsics.checkNotNullParameter(this_with2, "$this_with");
                boolean zIsChecked2 = ((SwitchCompat) this_with2.h).isChecked();
                com.onetrust.otpublishers.headless.UI.viewmodel.e eVarX = this$06.X();
                OTPublishersHeadlessSDK oTPublishersHeadlessSDK2 = eVarX.f;
                if (oTPublishersHeadlessSDK2 != null) {
                    oTPublishersHeadlessSDK2.updateAllVendorsConsentLocal((String) AbstractC3665l4.a(eVarX.i), zIsChecked2);
                }
                eVarX.D();
                return;
            case 16:
                ((com.quizlet.edgy.ui.recyclerview.viewholder.c) obj2).d.invoke((com.quizlet.edgy.ui.recyclerview.adapter.d) obj);
                return;
            case 17:
                ((com.quizlet.edgy.ui.recyclerview.viewholder.e) obj2).d.invoke((com.quizlet.edgy.ui.recyclerview.adapter.g) obj);
                return;
            case 18:
                ((com.quizlet.edgy.ui.recyclerview.viewholder.f) obj2).d.invoke((i) obj);
                return;
            case 19:
                ((Menu) obj2).performIdentifierAction(((MenuItem) obj).getItemId(), 0);
                return;
            case 20:
                CreatedFolderWithCreator item = (CreatedFolderWithCreator) obj;
                com.quizlet.data.interactor.course.a aVar = (com.quizlet.data.interactor.course.a) obj2;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(item, "item");
                WeakReference weakReference = ((UserFolderListFragment) aVar.b).v;
                if (weakReference == null) {
                    Intrinsics.m("mDelegate");
                    throw null;
                }
                t tVar = (t) weakReference.get();
                if (tVar != null) {
                    long jA = item.a.a();
                    ProfileFragment profileFragment = (ProfileFragment) tVar;
                    String str = FolderActivity.j;
                    Context contextRequireContext = profileFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    profileFragment.startActivity(AbstractC3309z0.b(contextRequireContext, jA));
                    return;
                }
                return;
            case 21:
                int i = SegmentedBucketLayout2.a;
                ((View.OnClickListener) obj2).onClick(view);
                Intrinsics.d(view);
                SegmentedBucketLayout2 segmentedBucketLayout2 = (SegmentedBucketLayout2) obj;
                segmentedBucketLayout2.getClass();
                com.quizlet.features.infra.legacyadapter.databinding.h hVarB = com.quizlet.features.infra.legacyadapter.databinding.h.b(view);
                Intrinsics.checkNotNullExpressionValue(hVarB, "bind(...)");
                int childCount = segmentedBucketLayout2.getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    com.quizlet.features.infra.legacyadapter.databinding.h hVarB2 = com.quizlet.features.infra.legacyadapter.databinding.h.b(segmentedBucketLayout2.getChildAt(i2));
                    Intrinsics.checkNotNullExpressionValue(hVarB2, "bind(...)");
                    CardView cardView = (CardView) hVarB2.e;
                    boolean zB = Intrinsics.b(cardView, view);
                    View view2 = (View) hVarB2.f;
                    if (zB) {
                        cardView.setCardElevation(segmentedBucketLayout2.getResources().getDimensionPixelSize(R.dimen.bucket_elevation_selected));
                        view2.setBackgroundColor(((QTextView) hVarB.b).getCurrentTextColor());
                    } else {
                        cardView.setCardElevation(segmentedBucketLayout2.getResources().getDimensionPixelSize(R.dimen.bucket_elevation));
                        view2.setBackground(null);
                    }
                }
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.quizletandroid.ui.group.classcontent.adapter.c cVar = (com.quizlet.quizletandroid.ui.group.classcontent.adapter.c) obj;
                cVar.getAdapterPosition();
                com.quizlet.quizletandroid.ui.group.classcontent.models.c cVar2 = cVar.b;
                if (cVar2 != null) {
                    ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) obj2).B(cVar2);
                    return;
                } else {
                    Intrinsics.m("folder");
                    throw null;
                }
            case EventType.AUDIO /* 23 */:
                com.quizlet.quizletandroid.ui.group.classcontent.adapter.e eVar4 = (com.quizlet.quizletandroid.ui.group.classcontent.adapter.e) obj;
                eVar4.getAdapterPosition();
                com.quizlet.quizletandroid.ui.group.classcontent.models.d dVar = eVar4.b;
                if (dVar != null) {
                    ((com.quizlet.quizletandroid.ui.group.classcontent.viewmodel.a) obj2).B(dVar);
                    return;
                } else {
                    Intrinsics.m("set");
                    throw null;
                }
            case EventType.VIDEO /* 24 */:
                ((com.quizlet.quizletandroid.ui.setcreation.viewholders.a) obj2).a.accept((String) obj);
                return;
            case EventType.SUBS /* 25 */:
                com.quizlet.quizletandroid.ui.setpage.b bVar2 = (com.quizlet.quizletandroid.ui.setpage.b) obj2;
                bVar2.getParentFragmentManager().g0(AbstractC3206m6.a(new Pair("ADD_IMAGE_RESULT_KEY", (com.quizlet.quizletandroid.ui.setpage.a) obj)), "ADD_IMAGE_REQUEST_KEY");
                Dialog dialog = bVar2.l;
                if (dialog != null) {
                    dialog.dismiss();
                    return;
                }
                return;
            case EventType.CDN /* 26 */:
                int i3 = WriteModeResultsView.q;
                QStarIconView qStarIconView = (QStarIconView) obj2;
                com.quizlet.quizletandroid.ui.common.adapter.b bVar3 = (com.quizlet.quizletandroid.ui.common.adapter.b) obj;
                if (qStarIconView.isSelected()) {
                    qStarIconView.setSelected(false);
                    bVar3.g(false);
                    return;
                } else {
                    qStarIconView.setSelected(true);
                    bVar3.g(true);
                    return;
                }
            case 27:
                Function1 function1 = ((QRichTextToolbar) obj2).e;
                if (function1 != null) {
                    function1.invoke((com.quizlet.richtext.ui.toolbar.c) obj);
                    return;
                }
                return;
            case 28:
                ((com.quizlet.uicommon.ui.common.overflowmenu.f) obj2).d.invoke();
                ((com.quizlet.uicommon.ui.common.overflowmenu.e) obj).d.invoke();
                return;
            default:
                ((com.quizlet.upgrade.ui.featurelist.b) obj2).d.j((v) obj);
                return;
        }
    }

    public /* synthetic */ a(com.quizlet.data.interactor.course.a aVar, int i, CreatedFolderWithCreator createdFolderWithCreator) {
        this.a = 20;
        this.b = aVar;
        this.c = createdFolderWithCreator;
    }
}
