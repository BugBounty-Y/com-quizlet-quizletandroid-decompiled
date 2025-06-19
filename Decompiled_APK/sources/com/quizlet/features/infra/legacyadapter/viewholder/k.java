package com.quizlet.features.infra.legacyadapter.viewholder;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_barcode.C6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.legacyadapter.common.ListitemPressIndicatorLine;
import com.quizlet.features.infra.legacyadapter.common.UserListTitleView;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import io.reactivex.rxjava3.core.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends com.quizlet.baserecyclerview.c implements i {
    public static final /* synthetic */ int g = 0;
    public final com.quizlet.qutils.image.loading.a d;
    public final com.quizlet.infra.legacysyncengine.managers.d e;
    public io.reactivex.rxjava3.internal.observers.e f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(View itemView) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        u uVar = (u) ((com.quizlet.features.infra.legacyadapter.di.a) K6.b(com.quizlet.features.infra.legacyadapter.di.a.class, itemView.getContext().getApplicationContext()));
        this.d = (com.quizlet.qutils.image.loading.a) uVar.s.get();
        this.e = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
    }

    public static void f(k kVar, DBStudySet studySet, boolean z, p isAvailable, boolean z2) {
        String quantityString;
        kVar.getClass();
        Intrinsics.checkNotNullParameter(studySet, "studySet");
        Intrinsics.checkNotNullParameter(isAvailable, "isAvailable");
        ConstraintLayout listitemSetCardLayout = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).b;
        Intrinsics.checkNotNullExpressionValue(listitemSetCardLayout, "listitemSetCardLayout");
        listitemSetCardLayout.setAlpha(z2 ? 0.5f : 1.0f);
        kVar.h(isAvailable);
        DBUser creator = studySet.getCreator();
        Creator creatorB = creator != null ? C6.b(creator) : null;
        long creatorId = studySet.getCreatorId();
        if (creatorB != null) {
            com.quizlet.infra.legacysyncengine.managers.d dVar = kVar.e;
            if (dVar == null) {
                Intrinsics.m("loggedInUserManager");
                throw null;
            }
            DBUser dBUser = dVar.r;
            if (dBUser == null || creatorId != dBUser.getId()) {
                UserListTitleView listitemSetUser = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).g;
                Intrinsics.checkNotNullExpressionValue(listitemSetUser, "listitemSetUser");
                listitemSetUser.setUser(creatorB);
            } else {
                UserListTitleView listitemSetUser2 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).g;
                Intrinsics.checkNotNullExpressionValue(listitemSetUser2, "listitemSetUser");
                listitemSetUser2.setUser(dBUser);
            }
        } else {
            UserListTitleView listitemSetUser3 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).g;
            Intrinsics.checkNotNullExpressionValue(listitemSetUser3, "listitemSetUser");
            listitemSetUser3.setVisibility(4);
        }
        QTextView listitemSetDetailTermCount = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).c;
        Intrinsics.checkNotNullExpressionValue(listitemSetDetailTermCount, "listitemSetDetailTermCount");
        QTextView listitemSetDetailTermCount2 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).c;
        Intrinsics.checkNotNullExpressionValue(listitemSetDetailTermCount2, "listitemSetDetailTermCount");
        Context context = listitemSetDetailTermCount2.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        int numTerms = studySet.getNumTerms();
        String quantityString2 = context.getResources().getQuantityString(R.plurals.terms, numTerms, Integer.valueOf(numTerms));
        Intrinsics.checkNotNullExpressionValue(quantityString2, "getQuantityString(...)");
        listitemSetDetailTermCount.setText(quantityString2);
        QTextView listitemSetTitle = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).f;
        Intrinsics.checkNotNullExpressionValue(listitemSetTitle, "listitemSetTitle");
        Context context2 = listitemSetTitle.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        String title = studySet.getTitle();
        boolean isCreated = studySet.getIsCreated();
        Intrinsics.checkNotNullParameter(context2, "context");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder();
        Intrinsics.checkNotNullParameter(context2, "context");
        if (title == null || title.length() == 0) {
            title = context2.getString(R.string.untitled_set);
            Intrinsics.d(title);
        }
        if (!isCreated) {
            title = context2.getString(R.string.draft_set_formatter, title);
            spannableStringBuilder.setSpan(new ForegroundColorSpan(com.quizlet.themes.extensions.a.a(context2, R.attr.textColorDraft)), 0, 0, 18);
        }
        spannableStringBuilder.append((CharSequence) title);
        QTextView listitemSetTitle2 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).f;
        Intrinsics.checkNotNullExpressionValue(listitemSetTitle2, "listitemSetTitle");
        listitemSetTitle2.setText(spannableStringBuilder);
        Context context3 = kVar.itemView.getContext();
        Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
        String title2 = studySet.getTitle();
        int numTerms2 = studySet.getNumTerms();
        DBUser creator2 = studySet.getCreator();
        Creator creatorB2 = creator2 != null ? C6.b(creator2) : null;
        Intrinsics.checkNotNullParameter(context3, "context");
        if (creatorB2 == null) {
            quantityString = context3.getResources().getQuantityString(R.plurals.study_set_description_no_creator, numTerms2, title2, Integer.valueOf(numTerms2));
            Intrinsics.d(quantityString);
        } else {
            quantityString = context3.getResources().getQuantityString(R.plurals.study_set_description, numTerms2, title2, creatorB2.b, Integer.valueOf(numTerms2));
            Intrinsics.d(quantityString);
        }
        kVar.itemView.setContentDescription(quantityString);
        String thumbnailUrl = studySet.getThumbnailUrl();
        if (thumbnailUrl == null || thumbnailUrl.length() == 0) {
            kVar.g().setVisibility(8);
            kVar.g().setImageDrawable(null);
        } else {
            kVar.g().setVisibility(0);
            com.quizlet.qutils.image.loading.a aVar = kVar.d;
            if (aVar == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar).a(kVar.itemView.getContext()).p(thumbnailUrl).o(kVar.g());
        }
        ImageView listitemSetLockIcon = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).e;
        Intrinsics.checkNotNullExpressionValue(listitemSetLockIcon, "listitemSetLockIcon");
        listitemSetLockIcon.setVisibility(studySet.isVisibilityRestricted() ? 0 : 8);
        if (z) {
            ConstraintLayout listitemSetCardLayout2 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).b;
            Intrinsics.checkNotNullExpressionValue(listitemSetCardLayout2, "listitemSetCardLayout");
            listitemSetCardLayout2.setBackgroundResource(R.drawable.accent_rectangle_border);
        } else {
            ConstraintLayout listitemSetCardLayout3 = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).b;
            Intrinsics.checkNotNullExpressionValue(listitemSetCardLayout3, "listitemSetCardLayout");
            listitemSetCardLayout3.setBackground(null);
        }
        studySet.getSetId();
        TextView recommendedText = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).i;
        Intrinsics.checkNotNullExpressionValue(recommendedText, "recommendedText");
        recommendedText.setVisibility(4);
        ImageView moreButton = ((com.quizlet.features.infra.legacyadapter.databinding.g) kVar.e()).h;
        Intrinsics.checkNotNullExpressionValue(moreButton, "moreButton");
        moreButton.setVisibility(8);
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void a(View.OnClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        View itemView = this.itemView;
        Intrinsics.checkNotNullExpressionValue(itemView, "itemView");
        com.facebook.appevents.m.o(itemView).u(new d(listener, 1), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    @Override // com.quizlet.features.infra.legacyadapter.viewholder.i
    public final void b(View.OnLongClickListener listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.itemView.setOnLongClickListener(listener);
    }

    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        Void item = (Void) obj;
        Intrinsics.checkNotNullParameter(item, "item");
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        int i = R.id.listitemPressIndicatorLine;
        if (((ListitemPressIndicatorLine) AbstractC3375o2.c(R.id.listitemPressIndicatorLine, view)) != null) {
            CardView cardView = (CardView) view;
            i = R.id.listitem_set_card_layout;
            ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.listitem_set_card_layout, view);
            if (constraintLayout != null) {
                i = R.id.listitem_set_detail_term_count;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.listitem_set_detail_term_count, view);
                if (qTextView != null) {
                    i = R.id.listitem_set_diagram_preview_image;
                    ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.listitem_set_diagram_preview_image, view);
                    if (imageView != null) {
                        i = R.id.listitem_set_lock_icon;
                        ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.listitem_set_lock_icon, view);
                        if (imageView2 != null) {
                            i = R.id.listitem_set_title;
                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.listitem_set_title, view);
                            if (qTextView2 != null) {
                                i = R.id.listitem_set_user;
                                UserListTitleView userListTitleView = (UserListTitleView) AbstractC3375o2.c(R.id.listitem_set_user, view);
                                if (userListTitleView != null) {
                                    i = R.id.moreButton;
                                    ImageView imageView3 = (ImageView) AbstractC3375o2.c(R.id.moreButton, view);
                                    if (imageView3 != null) {
                                        i = R.id.recommendedText;
                                        TextView textView = (TextView) AbstractC3375o2.c(R.id.recommendedText, view);
                                        if (textView != null) {
                                            com.quizlet.features.infra.legacyadapter.databinding.g gVar = new com.quizlet.features.infra.legacyadapter.databinding.g(cardView, constraintLayout, qTextView, imageView, imageView2, qTextView2, userListTitleView, imageView3, textView);
                                            Intrinsics.checkNotNullExpressionValue(gVar, "bind(...)");
                                            return gVar;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public final ImageView g() {
        ImageView listitemSetDiagramPreviewImage = ((com.quizlet.features.infra.legacyadapter.databinding.g) e()).d;
        Intrinsics.checkNotNullExpressionValue(listitemSetDiagramPreviewImage, "listitemSetDiagramPreviewImage");
        return listitemSetDiagramPreviewImage;
    }

    public final void h(p isAvailable) {
        io.reactivex.rxjava3.internal.observers.e eVar;
        Intrinsics.checkNotNullParameter(isAvailable, "isAvailable");
        io.reactivex.rxjava3.internal.observers.e eVar2 = this.f;
        if (eVar2 != null && !eVar2.b() && (eVar = this.f) != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(eVar);
        }
        this.f = isAvailable.g(j.a).i(new com.quizlet.analytics.marketing.e(this, 4), new com.quizlet.billing.manager.d(timber.log.c.a, 2));
    }
}
