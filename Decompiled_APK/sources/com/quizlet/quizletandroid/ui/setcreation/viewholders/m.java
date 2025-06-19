package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.content.Intent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.appcompat.app.K;
import androidx.core.view.C1043d0;
import androidx.core.view.V;
import androidx.recyclerview.widget.F0;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.onetrust.otpublishers.headless.UI.adapter.ViewOnClickListenerC4055k;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditTermImagePreviewActivity;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardFocusPosition;
import com.quizlet.uicommon.ui.common.dialogs.e;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends F0 implements com.quizlet.quizletandroid.ui.setcreation.callbacks.a {
    public static float l;
    public static float m;
    public final com.onetrust.otpublishers.headless.databinding.d a;
    public final l b;
    public final l c;
    public final EventLogger d;
    public int e;
    public boolean f;
    public boolean g;
    public final com.quizlet.qutils.image.loading.a h;
    public final com.quizlet.quizletandroid.ui.setcreation.adapters.f i;
    public final K j;
    public final com.quizlet.login.authentication.login.a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(com.quizlet.quizletandroid.ui.setcreation.adapters.f presenter, View itemView, com.quizlet.qutils.image.loading.a imageLoader, io.reactivex.rxjava3.core.i showImageButton, K scrollingStatusObserver, androidx.work.impl.model.c userProps) {
        super(itemView);
        Intrinsics.checkNotNullParameter(presenter, "presenter");
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        Intrinsics.checkNotNullParameter(showImageButton, "showImageButton");
        Intrinsics.checkNotNullParameter(scrollingStatusObserver, "scrollingStatusObserver");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        int i = R.id.edit_set_add_term_below_button;
        IconFontTextView editSetAddTermBelowButton = (IconFontTextView) AbstractC3375o2.c(R.id.edit_set_add_term_below_button, itemView);
        if (editSetAddTermBelowButton != null) {
            i = R.id.edit_set_def_image;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.edit_set_def_image, itemView);
            if (imageView != null) {
                i = R.id.edit_set_def_image_container;
                FrameLayout editSetDefImageContainer = (FrameLayout) AbstractC3375o2.c(R.id.edit_set_def_image_container, itemView);
                if (editSetDefImageContainer != null) {
                    i = R.id.edit_set_def_suggestions;
                    LinearLayout editSetDefSuggestions = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_def_suggestions, itemView);
                    if (editSetDefSuggestions != null) {
                        i = R.id.edit_set_definition_field;
                        QRichFormField qRichFormField = (QRichFormField) AbstractC3375o2.c(R.id.edit_set_definition_field, itemView);
                        if (qRichFormField != null) {
                            i = R.id.edit_set_delete_term_button;
                            IconFontTextView editSetDeleteTermButton = (IconFontTextView) AbstractC3375o2.c(R.id.edit_set_delete_term_button, itemView);
                            if (editSetDeleteTermButton != null) {
                                i = R.id.edit_set_edit_term_card;
                                LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_edit_term_card, itemView);
                                if (linearLayout != null) {
                                    i = R.id.edit_set_hidden_button_panel;
                                    LinearLayout linearLayout2 = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_hidden_button_panel, itemView);
                                    if (linearLayout2 != null) {
                                        i = R.id.edit_set_word_field;
                                        QRichFormField qRichFormField2 = (QRichFormField) AbstractC3375o2.c(R.id.edit_set_word_field, itemView);
                                        if (qRichFormField2 != null) {
                                            i = R.id.edit_set_word_suggestions;
                                            LinearLayout editSetWordSuggestions = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_word_suggestions, itemView);
                                            if (editSetWordSuggestions != null) {
                                                com.onetrust.otpublishers.headless.databinding.d dVar = new com.onetrust.otpublishers.headless.databinding.d((FrameLayout) itemView, editSetAddTermBelowButton, imageView, editSetDefImageContainer, editSetDefSuggestions, qRichFormField, editSetDeleteTermButton, linearLayout, linearLayout2, qRichFormField2, editSetWordSuggestions);
                                                Intrinsics.checkNotNullExpressionValue(dVar, "bind(...)");
                                                this.a = dVar;
                                                this.k = new com.quizlet.login.authentication.login.a(this, 11);
                                                this.d = (EventLogger) ((u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, itemView.getContext().getApplicationContext()))).l0.get();
                                                this.i = presenter;
                                                this.h = imageLoader;
                                                QRichFormField qRichFormFieldH = h();
                                                Intrinsics.checkNotNullExpressionValue(editSetWordSuggestions, "editSetWordSuggestions");
                                                this.b = new l(this, true, qRichFormFieldH, editSetWordSuggestions, userProps);
                                                QRichFormField qRichFormFieldF = f();
                                                Intrinsics.checkNotNullExpressionValue(editSetDefSuggestions, "editSetDefSuggestions");
                                                this.c = new l(this, false, qRichFormFieldF, editSetDefSuggestions, userProps);
                                                if (l == DefinitionKt.NO_Float_VALUE) {
                                                    l = itemView.getContext().getResources().getDimension(R.dimen.quizlet_edge_margin);
                                                }
                                                e().setEnabled(false);
                                                this.j = scrollingStatusObserver;
                                                showImageButton.u(new i(this, 0), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
                                                Intrinsics.checkNotNullExpressionValue(editSetDeleteTermButton, "editSetDeleteTermButton");
                                                final int i2 = 0;
                                                editSetDeleteTermButton.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.h
                                                    public final /* synthetic */ m b;

                                                    {
                                                        this.b = this;
                                                    }

                                                    @Override // android.view.View.OnClickListener
                                                    public final void onClick(View view) {
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                                                        ArrayList arrayList;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar3;
                                                        int i3 = 2;
                                                        m mVar = this.b;
                                                        switch (i2) {
                                                            case 0:
                                                                int adapterPosition = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                                                                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                                                                if (aVar2 != null) {
                                                                    fVar.m();
                                                                    if (fVar.p.size() > 2) {
                                                                        DBTerm dbTerm = fVar.j(adapterPosition);
                                                                        if (dbTerm != null) {
                                                                            int i4 = adapterPosition - 1;
                                                                            if (fVar.k() != null) {
                                                                                com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar.k();
                                                                                Long lValueOf = Long.valueOf(dbTerm.getLocalId());
                                                                                Long lValueOf2 = Long.valueOf(dbTerm.getId());
                                                                                aVarK.g();
                                                                                aVarK.a("delete", lValueOf, lValueOf2).d();
                                                                            }
                                                                            fVar.p.remove(dbTerm);
                                                                            ArrayList terms = fVar.p;
                                                                            EditSetFragment editSetFragment = (EditSetFragment) aVar2;
                                                                            Intrinsics.checkNotNullParameter(dbTerm, "dbTerm");
                                                                            Intrinsics.checkNotNullParameter(terms, "terms");
                                                                            WeakReference weakReference = editSetFragment.x;
                                                                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                                                                editSetFragment.h0();
                                                                                ViewOnClickListenerC4055k viewOnClickListenerC4055k = new ViewOnClickListenerC4055k(editSetFragment, i4, dbTerm, i3);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = new com.quizlet.quizletandroid.ui.setcreation.fragments.i(bVar2, dbTerm, i4, terms);
                                                                                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2;
                                                                                String string = dVar2.getString(R.string.undo_delete_snackbar_action);
                                                                                com.google.android.material.snackbar.h hVarD = I6.d(dVar2.E, dVar2.getString(R.string.undo_delete_snackbar_text));
                                                                                hVarD.h(string, viewOnClickListenerC4055k);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar2 = hVarD.D;
                                                                                if (iVar2 != null && (arrayList = hVarD.s) != null) {
                                                                                    arrayList.remove(iVar2);
                                                                                }
                                                                                if (hVarD.s == null) {
                                                                                    hVarD.s = new ArrayList();
                                                                                }
                                                                                hVarD.s.add(iVar);
                                                                                hVarD.D = iVar;
                                                                                hVarD.i();
                                                                            }
                                                                            fVar.notifyItemRemoved(adapterPosition);
                                                                            ArrayList terms2 = fVar.p;
                                                                            Intrinsics.checkNotNullParameter(terms2, "terms");
                                                                            WeakReference weakReference2 = editSetFragment.x;
                                                                            if (weakReference2 != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get()) != null) {
                                                                                ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(i4, terms2);
                                                                                editSetFragment.h0();
                                                                            }
                                                                            int i5 = fVar.j;
                                                                            if (i5 > adapterPosition) {
                                                                                fVar.k.b(new CardFocusPosition(i5 - 2, i5, O1.WORD));
                                                                                break;
                                                                            }
                                                                        }
                                                                    } else {
                                                                        e.a aVar3 = new e.a(((EditSetFragment) aVar2).requireContext());
                                                                        aVar3.f(R.string.edit_set_at_least_two_terms_dialog_title);
                                                                        aVar3.c(R.string.edit_set_at_least_two_terms_dialog_message);
                                                                        aVar3.b = false;
                                                                        aVar3.i = aVar3.a.getString(R.string.OK);
                                                                        aVar3.j = null;
                                                                        aVar3.g();
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 1:
                                                                int adapterPosition2 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                                                                fVar2.m();
                                                                DBTerm dBTermJ = fVar2.j(adapterPosition2);
                                                                if (dBTermJ != null && fVar2.k() != null) {
                                                                    com.quizlet.quizletandroid.sessionhelpers.a aVarK2 = fVar2.k();
                                                                    Long lValueOf3 = Long.valueOf(dBTermJ.getLocalId());
                                                                    Long lValueOf4 = Long.valueOf(dBTermJ.getId());
                                                                    aVarK2.g();
                                                                    aVarK2.a("add_term_after", lValueOf3, lValueOf4).d();
                                                                }
                                                                fVar2.d(adapterPosition2);
                                                                break;
                                                            case 2:
                                                                int adapterPosition3 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = mVar.i;
                                                                fVar3.m();
                                                                DBTerm term = fVar3.j(adapterPosition3);
                                                                if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar3.r.get()) != null) {
                                                                    Intrinsics.checkNotNullParameter(term, "term");
                                                                    WeakReference weakReference3 = ((EditSetFragment) aVar).x;
                                                                    if (weakReference3 != null && (bVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference3.get()) != null) {
                                                                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar3;
                                                                        String definitionImageLargeUrl = term.getDefinitionImageLargeUrl();
                                                                        Long lValueOf5 = Long.valueOf(term.getLocalId());
                                                                        Long lValueOf6 = Long.valueOf(term.getId());
                                                                        int i6 = EditTermImagePreviewActivity.t;
                                                                        Intent intent = new Intent(dVar3, (Class<?>) EditTermImagePreviewActivity.class);
                                                                        intent.putExtra("overlayImagePath", definitionImageLargeUrl);
                                                                        intent.putExtra("termLocalId", lValueOf5);
                                                                        intent.putExtra("termId", lValueOf6);
                                                                        dVar3.startActivityForResult(intent, 1000);
                                                                        dVar3.overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 3:
                                                                mVar.h().requestFocus();
                                                                break;
                                                            default:
                                                                mVar.f().requestFocus();
                                                                break;
                                                        }
                                                    }
                                                });
                                                Intrinsics.checkNotNullExpressionValue(editSetAddTermBelowButton, "editSetAddTermBelowButton");
                                                final int i3 = 1;
                                                editSetAddTermBelowButton.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.h
                                                    public final /* synthetic */ m b;

                                                    {
                                                        this.b = this;
                                                    }

                                                    @Override // android.view.View.OnClickListener
                                                    public final void onClick(View view) {
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                                                        ArrayList arrayList;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar3;
                                                        int i32 = 2;
                                                        m mVar = this.b;
                                                        switch (i3) {
                                                            case 0:
                                                                int adapterPosition = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                                                                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                                                                if (aVar2 != null) {
                                                                    fVar.m();
                                                                    if (fVar.p.size() > 2) {
                                                                        DBTerm dbTerm = fVar.j(adapterPosition);
                                                                        if (dbTerm != null) {
                                                                            int i4 = adapterPosition - 1;
                                                                            if (fVar.k() != null) {
                                                                                com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar.k();
                                                                                Long lValueOf = Long.valueOf(dbTerm.getLocalId());
                                                                                Long lValueOf2 = Long.valueOf(dbTerm.getId());
                                                                                aVarK.g();
                                                                                aVarK.a("delete", lValueOf, lValueOf2).d();
                                                                            }
                                                                            fVar.p.remove(dbTerm);
                                                                            ArrayList terms = fVar.p;
                                                                            EditSetFragment editSetFragment = (EditSetFragment) aVar2;
                                                                            Intrinsics.checkNotNullParameter(dbTerm, "dbTerm");
                                                                            Intrinsics.checkNotNullParameter(terms, "terms");
                                                                            WeakReference weakReference = editSetFragment.x;
                                                                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                                                                editSetFragment.h0();
                                                                                ViewOnClickListenerC4055k viewOnClickListenerC4055k = new ViewOnClickListenerC4055k(editSetFragment, i4, dbTerm, i32);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = new com.quizlet.quizletandroid.ui.setcreation.fragments.i(bVar2, dbTerm, i4, terms);
                                                                                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2;
                                                                                String string = dVar2.getString(R.string.undo_delete_snackbar_action);
                                                                                com.google.android.material.snackbar.h hVarD = I6.d(dVar2.E, dVar2.getString(R.string.undo_delete_snackbar_text));
                                                                                hVarD.h(string, viewOnClickListenerC4055k);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar2 = hVarD.D;
                                                                                if (iVar2 != null && (arrayList = hVarD.s) != null) {
                                                                                    arrayList.remove(iVar2);
                                                                                }
                                                                                if (hVarD.s == null) {
                                                                                    hVarD.s = new ArrayList();
                                                                                }
                                                                                hVarD.s.add(iVar);
                                                                                hVarD.D = iVar;
                                                                                hVarD.i();
                                                                            }
                                                                            fVar.notifyItemRemoved(adapterPosition);
                                                                            ArrayList terms2 = fVar.p;
                                                                            Intrinsics.checkNotNullParameter(terms2, "terms");
                                                                            WeakReference weakReference2 = editSetFragment.x;
                                                                            if (weakReference2 != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get()) != null) {
                                                                                ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(i4, terms2);
                                                                                editSetFragment.h0();
                                                                            }
                                                                            int i5 = fVar.j;
                                                                            if (i5 > adapterPosition) {
                                                                                fVar.k.b(new CardFocusPosition(i5 - 2, i5, O1.WORD));
                                                                                break;
                                                                            }
                                                                        }
                                                                    } else {
                                                                        e.a aVar3 = new e.a(((EditSetFragment) aVar2).requireContext());
                                                                        aVar3.f(R.string.edit_set_at_least_two_terms_dialog_title);
                                                                        aVar3.c(R.string.edit_set_at_least_two_terms_dialog_message);
                                                                        aVar3.b = false;
                                                                        aVar3.i = aVar3.a.getString(R.string.OK);
                                                                        aVar3.j = null;
                                                                        aVar3.g();
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 1:
                                                                int adapterPosition2 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                                                                fVar2.m();
                                                                DBTerm dBTermJ = fVar2.j(adapterPosition2);
                                                                if (dBTermJ != null && fVar2.k() != null) {
                                                                    com.quizlet.quizletandroid.sessionhelpers.a aVarK2 = fVar2.k();
                                                                    Long lValueOf3 = Long.valueOf(dBTermJ.getLocalId());
                                                                    Long lValueOf4 = Long.valueOf(dBTermJ.getId());
                                                                    aVarK2.g();
                                                                    aVarK2.a("add_term_after", lValueOf3, lValueOf4).d();
                                                                }
                                                                fVar2.d(adapterPosition2);
                                                                break;
                                                            case 2:
                                                                int adapterPosition3 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = mVar.i;
                                                                fVar3.m();
                                                                DBTerm term = fVar3.j(adapterPosition3);
                                                                if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar3.r.get()) != null) {
                                                                    Intrinsics.checkNotNullParameter(term, "term");
                                                                    WeakReference weakReference3 = ((EditSetFragment) aVar).x;
                                                                    if (weakReference3 != null && (bVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference3.get()) != null) {
                                                                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar3;
                                                                        String definitionImageLargeUrl = term.getDefinitionImageLargeUrl();
                                                                        Long lValueOf5 = Long.valueOf(term.getLocalId());
                                                                        Long lValueOf6 = Long.valueOf(term.getId());
                                                                        int i6 = EditTermImagePreviewActivity.t;
                                                                        Intent intent = new Intent(dVar3, (Class<?>) EditTermImagePreviewActivity.class);
                                                                        intent.putExtra("overlayImagePath", definitionImageLargeUrl);
                                                                        intent.putExtra("termLocalId", lValueOf5);
                                                                        intent.putExtra("termId", lValueOf6);
                                                                        dVar3.startActivityForResult(intent, 1000);
                                                                        dVar3.overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 3:
                                                                mVar.h().requestFocus();
                                                                break;
                                                            default:
                                                                mVar.f().requestFocus();
                                                                break;
                                                        }
                                                    }
                                                });
                                                Intrinsics.checkNotNullExpressionValue(editSetDefImageContainer, "editSetDefImageContainer");
                                                final int i4 = 2;
                                                editSetDefImageContainer.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.h
                                                    public final /* synthetic */ m b;

                                                    {
                                                        this.b = this;
                                                    }

                                                    @Override // android.view.View.OnClickListener
                                                    public final void onClick(View view) {
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                                                        ArrayList arrayList;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar3;
                                                        int i32 = 2;
                                                        m mVar = this.b;
                                                        switch (i4) {
                                                            case 0:
                                                                int adapterPosition = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                                                                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                                                                if (aVar2 != null) {
                                                                    fVar.m();
                                                                    if (fVar.p.size() > 2) {
                                                                        DBTerm dbTerm = fVar.j(adapterPosition);
                                                                        if (dbTerm != null) {
                                                                            int i42 = adapterPosition - 1;
                                                                            if (fVar.k() != null) {
                                                                                com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar.k();
                                                                                Long lValueOf = Long.valueOf(dbTerm.getLocalId());
                                                                                Long lValueOf2 = Long.valueOf(dbTerm.getId());
                                                                                aVarK.g();
                                                                                aVarK.a("delete", lValueOf, lValueOf2).d();
                                                                            }
                                                                            fVar.p.remove(dbTerm);
                                                                            ArrayList terms = fVar.p;
                                                                            EditSetFragment editSetFragment = (EditSetFragment) aVar2;
                                                                            Intrinsics.checkNotNullParameter(dbTerm, "dbTerm");
                                                                            Intrinsics.checkNotNullParameter(terms, "terms");
                                                                            WeakReference weakReference = editSetFragment.x;
                                                                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                                                                editSetFragment.h0();
                                                                                ViewOnClickListenerC4055k viewOnClickListenerC4055k = new ViewOnClickListenerC4055k(editSetFragment, i42, dbTerm, i32);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = new com.quizlet.quizletandroid.ui.setcreation.fragments.i(bVar2, dbTerm, i42, terms);
                                                                                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2;
                                                                                String string = dVar2.getString(R.string.undo_delete_snackbar_action);
                                                                                com.google.android.material.snackbar.h hVarD = I6.d(dVar2.E, dVar2.getString(R.string.undo_delete_snackbar_text));
                                                                                hVarD.h(string, viewOnClickListenerC4055k);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar2 = hVarD.D;
                                                                                if (iVar2 != null && (arrayList = hVarD.s) != null) {
                                                                                    arrayList.remove(iVar2);
                                                                                }
                                                                                if (hVarD.s == null) {
                                                                                    hVarD.s = new ArrayList();
                                                                                }
                                                                                hVarD.s.add(iVar);
                                                                                hVarD.D = iVar;
                                                                                hVarD.i();
                                                                            }
                                                                            fVar.notifyItemRemoved(adapterPosition);
                                                                            ArrayList terms2 = fVar.p;
                                                                            Intrinsics.checkNotNullParameter(terms2, "terms");
                                                                            WeakReference weakReference2 = editSetFragment.x;
                                                                            if (weakReference2 != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get()) != null) {
                                                                                ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(i42, terms2);
                                                                                editSetFragment.h0();
                                                                            }
                                                                            int i5 = fVar.j;
                                                                            if (i5 > adapterPosition) {
                                                                                fVar.k.b(new CardFocusPosition(i5 - 2, i5, O1.WORD));
                                                                                break;
                                                                            }
                                                                        }
                                                                    } else {
                                                                        e.a aVar3 = new e.a(((EditSetFragment) aVar2).requireContext());
                                                                        aVar3.f(R.string.edit_set_at_least_two_terms_dialog_title);
                                                                        aVar3.c(R.string.edit_set_at_least_two_terms_dialog_message);
                                                                        aVar3.b = false;
                                                                        aVar3.i = aVar3.a.getString(R.string.OK);
                                                                        aVar3.j = null;
                                                                        aVar3.g();
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 1:
                                                                int adapterPosition2 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                                                                fVar2.m();
                                                                DBTerm dBTermJ = fVar2.j(adapterPosition2);
                                                                if (dBTermJ != null && fVar2.k() != null) {
                                                                    com.quizlet.quizletandroid.sessionhelpers.a aVarK2 = fVar2.k();
                                                                    Long lValueOf3 = Long.valueOf(dBTermJ.getLocalId());
                                                                    Long lValueOf4 = Long.valueOf(dBTermJ.getId());
                                                                    aVarK2.g();
                                                                    aVarK2.a("add_term_after", lValueOf3, lValueOf4).d();
                                                                }
                                                                fVar2.d(adapterPosition2);
                                                                break;
                                                            case 2:
                                                                int adapterPosition3 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = mVar.i;
                                                                fVar3.m();
                                                                DBTerm term = fVar3.j(adapterPosition3);
                                                                if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar3.r.get()) != null) {
                                                                    Intrinsics.checkNotNullParameter(term, "term");
                                                                    WeakReference weakReference3 = ((EditSetFragment) aVar).x;
                                                                    if (weakReference3 != null && (bVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference3.get()) != null) {
                                                                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar3;
                                                                        String definitionImageLargeUrl = term.getDefinitionImageLargeUrl();
                                                                        Long lValueOf5 = Long.valueOf(term.getLocalId());
                                                                        Long lValueOf6 = Long.valueOf(term.getId());
                                                                        int i6 = EditTermImagePreviewActivity.t;
                                                                        Intent intent = new Intent(dVar3, (Class<?>) EditTermImagePreviewActivity.class);
                                                                        intent.putExtra("overlayImagePath", definitionImageLargeUrl);
                                                                        intent.putExtra("termLocalId", lValueOf5);
                                                                        intent.putExtra("termId", lValueOf6);
                                                                        dVar3.startActivityForResult(intent, 1000);
                                                                        dVar3.overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 3:
                                                                mVar.h().requestFocus();
                                                                break;
                                                            default:
                                                                mVar.f().requestFocus();
                                                                break;
                                                        }
                                                    }
                                                });
                                                final int i5 = 3;
                                                h().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.h
                                                    public final /* synthetic */ m b;

                                                    {
                                                        this.b = this;
                                                    }

                                                    @Override // android.view.View.OnClickListener
                                                    public final void onClick(View view) {
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                                                        ArrayList arrayList;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar3;
                                                        int i32 = 2;
                                                        m mVar = this.b;
                                                        switch (i5) {
                                                            case 0:
                                                                int adapterPosition = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                                                                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                                                                if (aVar2 != null) {
                                                                    fVar.m();
                                                                    if (fVar.p.size() > 2) {
                                                                        DBTerm dbTerm = fVar.j(adapterPosition);
                                                                        if (dbTerm != null) {
                                                                            int i42 = adapterPosition - 1;
                                                                            if (fVar.k() != null) {
                                                                                com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar.k();
                                                                                Long lValueOf = Long.valueOf(dbTerm.getLocalId());
                                                                                Long lValueOf2 = Long.valueOf(dbTerm.getId());
                                                                                aVarK.g();
                                                                                aVarK.a("delete", lValueOf, lValueOf2).d();
                                                                            }
                                                                            fVar.p.remove(dbTerm);
                                                                            ArrayList terms = fVar.p;
                                                                            EditSetFragment editSetFragment = (EditSetFragment) aVar2;
                                                                            Intrinsics.checkNotNullParameter(dbTerm, "dbTerm");
                                                                            Intrinsics.checkNotNullParameter(terms, "terms");
                                                                            WeakReference weakReference = editSetFragment.x;
                                                                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                                                                editSetFragment.h0();
                                                                                ViewOnClickListenerC4055k viewOnClickListenerC4055k = new ViewOnClickListenerC4055k(editSetFragment, i42, dbTerm, i32);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = new com.quizlet.quizletandroid.ui.setcreation.fragments.i(bVar2, dbTerm, i42, terms);
                                                                                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2;
                                                                                String string = dVar2.getString(R.string.undo_delete_snackbar_action);
                                                                                com.google.android.material.snackbar.h hVarD = I6.d(dVar2.E, dVar2.getString(R.string.undo_delete_snackbar_text));
                                                                                hVarD.h(string, viewOnClickListenerC4055k);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar2 = hVarD.D;
                                                                                if (iVar2 != null && (arrayList = hVarD.s) != null) {
                                                                                    arrayList.remove(iVar2);
                                                                                }
                                                                                if (hVarD.s == null) {
                                                                                    hVarD.s = new ArrayList();
                                                                                }
                                                                                hVarD.s.add(iVar);
                                                                                hVarD.D = iVar;
                                                                                hVarD.i();
                                                                            }
                                                                            fVar.notifyItemRemoved(adapterPosition);
                                                                            ArrayList terms2 = fVar.p;
                                                                            Intrinsics.checkNotNullParameter(terms2, "terms");
                                                                            WeakReference weakReference2 = editSetFragment.x;
                                                                            if (weakReference2 != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get()) != null) {
                                                                                ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(i42, terms2);
                                                                                editSetFragment.h0();
                                                                            }
                                                                            int i52 = fVar.j;
                                                                            if (i52 > adapterPosition) {
                                                                                fVar.k.b(new CardFocusPosition(i52 - 2, i52, O1.WORD));
                                                                                break;
                                                                            }
                                                                        }
                                                                    } else {
                                                                        e.a aVar3 = new e.a(((EditSetFragment) aVar2).requireContext());
                                                                        aVar3.f(R.string.edit_set_at_least_two_terms_dialog_title);
                                                                        aVar3.c(R.string.edit_set_at_least_two_terms_dialog_message);
                                                                        aVar3.b = false;
                                                                        aVar3.i = aVar3.a.getString(R.string.OK);
                                                                        aVar3.j = null;
                                                                        aVar3.g();
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 1:
                                                                int adapterPosition2 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                                                                fVar2.m();
                                                                DBTerm dBTermJ = fVar2.j(adapterPosition2);
                                                                if (dBTermJ != null && fVar2.k() != null) {
                                                                    com.quizlet.quizletandroid.sessionhelpers.a aVarK2 = fVar2.k();
                                                                    Long lValueOf3 = Long.valueOf(dBTermJ.getLocalId());
                                                                    Long lValueOf4 = Long.valueOf(dBTermJ.getId());
                                                                    aVarK2.g();
                                                                    aVarK2.a("add_term_after", lValueOf3, lValueOf4).d();
                                                                }
                                                                fVar2.d(adapterPosition2);
                                                                break;
                                                            case 2:
                                                                int adapterPosition3 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = mVar.i;
                                                                fVar3.m();
                                                                DBTerm term = fVar3.j(adapterPosition3);
                                                                if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar3.r.get()) != null) {
                                                                    Intrinsics.checkNotNullParameter(term, "term");
                                                                    WeakReference weakReference3 = ((EditSetFragment) aVar).x;
                                                                    if (weakReference3 != null && (bVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference3.get()) != null) {
                                                                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar3;
                                                                        String definitionImageLargeUrl = term.getDefinitionImageLargeUrl();
                                                                        Long lValueOf5 = Long.valueOf(term.getLocalId());
                                                                        Long lValueOf6 = Long.valueOf(term.getId());
                                                                        int i6 = EditTermImagePreviewActivity.t;
                                                                        Intent intent = new Intent(dVar3, (Class<?>) EditTermImagePreviewActivity.class);
                                                                        intent.putExtra("overlayImagePath", definitionImageLargeUrl);
                                                                        intent.putExtra("termLocalId", lValueOf5);
                                                                        intent.putExtra("termId", lValueOf6);
                                                                        dVar3.startActivityForResult(intent, 1000);
                                                                        dVar3.overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 3:
                                                                mVar.h().requestFocus();
                                                                break;
                                                            default:
                                                                mVar.f().requestFocus();
                                                                break;
                                                        }
                                                    }
                                                });
                                                final int i6 = 4;
                                                f().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.viewholders.h
                                                    public final /* synthetic */ m b;

                                                    {
                                                        this.b = this;
                                                    }

                                                    @Override // android.view.View.OnClickListener
                                                    public final void onClick(View view) {
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar2;
                                                        ArrayList arrayList;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
                                                        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar3;
                                                        int i32 = 2;
                                                        m mVar = this.b;
                                                        switch (i6) {
                                                            case 0:
                                                                int adapterPosition = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
                                                                com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
                                                                if (aVar2 != null) {
                                                                    fVar.m();
                                                                    if (fVar.p.size() > 2) {
                                                                        DBTerm dbTerm = fVar.j(adapterPosition);
                                                                        if (dbTerm != null) {
                                                                            int i42 = adapterPosition - 1;
                                                                            if (fVar.k() != null) {
                                                                                com.quizlet.quizletandroid.sessionhelpers.a aVarK = fVar.k();
                                                                                Long lValueOf = Long.valueOf(dbTerm.getLocalId());
                                                                                Long lValueOf2 = Long.valueOf(dbTerm.getId());
                                                                                aVarK.g();
                                                                                aVarK.a("delete", lValueOf, lValueOf2).d();
                                                                            }
                                                                            fVar.p.remove(dbTerm);
                                                                            ArrayList terms = fVar.p;
                                                                            EditSetFragment editSetFragment = (EditSetFragment) aVar2;
                                                                            Intrinsics.checkNotNullParameter(dbTerm, "dbTerm");
                                                                            Intrinsics.checkNotNullParameter(terms, "terms");
                                                                            WeakReference weakReference = editSetFragment.x;
                                                                            if (weakReference != null && (bVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                                                                                editSetFragment.h0();
                                                                                ViewOnClickListenerC4055k viewOnClickListenerC4055k = new ViewOnClickListenerC4055k(editSetFragment, i42, dbTerm, i32);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar = new com.quizlet.quizletandroid.ui.setcreation.fragments.i(bVar2, dbTerm, i42, terms);
                                                                                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar2;
                                                                                String string = dVar2.getString(R.string.undo_delete_snackbar_action);
                                                                                com.google.android.material.snackbar.h hVarD = I6.d(dVar2.E, dVar2.getString(R.string.undo_delete_snackbar_text));
                                                                                hVarD.h(string, viewOnClickListenerC4055k);
                                                                                com.quizlet.quizletandroid.ui.setcreation.fragments.i iVar2 = hVarD.D;
                                                                                if (iVar2 != null && (arrayList = hVarD.s) != null) {
                                                                                    arrayList.remove(iVar2);
                                                                                }
                                                                                if (hVarD.s == null) {
                                                                                    hVarD.s = new ArrayList();
                                                                                }
                                                                                hVarD.s.add(iVar);
                                                                                hVarD.D = iVar;
                                                                                hVarD.i();
                                                                            }
                                                                            fVar.notifyItemRemoved(adapterPosition);
                                                                            ArrayList terms2 = fVar.p;
                                                                            Intrinsics.checkNotNullParameter(terms2, "terms");
                                                                            WeakReference weakReference2 = editSetFragment.x;
                                                                            if (weakReference2 != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference2.get()) != null) {
                                                                                ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).y.g(i42, terms2);
                                                                                editSetFragment.h0();
                                                                            }
                                                                            int i52 = fVar.j;
                                                                            if (i52 > adapterPosition) {
                                                                                fVar.k.b(new CardFocusPosition(i52 - 2, i52, O1.WORD));
                                                                                break;
                                                                            }
                                                                        }
                                                                    } else {
                                                                        e.a aVar3 = new e.a(((EditSetFragment) aVar2).requireContext());
                                                                        aVar3.f(R.string.edit_set_at_least_two_terms_dialog_title);
                                                                        aVar3.c(R.string.edit_set_at_least_two_terms_dialog_message);
                                                                        aVar3.b = false;
                                                                        aVar3.i = aVar3.a.getString(R.string.OK);
                                                                        aVar3.j = null;
                                                                        aVar3.g();
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 1:
                                                                int adapterPosition2 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar2 = mVar.i;
                                                                fVar2.m();
                                                                DBTerm dBTermJ = fVar2.j(adapterPosition2);
                                                                if (dBTermJ != null && fVar2.k() != null) {
                                                                    com.quizlet.quizletandroid.sessionhelpers.a aVarK2 = fVar2.k();
                                                                    Long lValueOf3 = Long.valueOf(dBTermJ.getLocalId());
                                                                    Long lValueOf4 = Long.valueOf(dBTermJ.getId());
                                                                    aVarK2.g();
                                                                    aVarK2.a("add_term_after", lValueOf3, lValueOf4).d();
                                                                }
                                                                fVar2.d(adapterPosition2);
                                                                break;
                                                            case 2:
                                                                int adapterPosition3 = mVar.getAdapterPosition();
                                                                com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar3 = mVar.i;
                                                                fVar3.m();
                                                                DBTerm term = fVar3.j(adapterPosition3);
                                                                if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar3.r.get()) != null) {
                                                                    Intrinsics.checkNotNullParameter(term, "term");
                                                                    WeakReference weakReference3 = ((EditSetFragment) aVar).x;
                                                                    if (weakReference3 != null && (bVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference3.get()) != null) {
                                                                        com.quizlet.quizletandroid.ui.setcreation.activities.d dVar3 = (com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar3;
                                                                        String definitionImageLargeUrl = term.getDefinitionImageLargeUrl();
                                                                        Long lValueOf5 = Long.valueOf(term.getLocalId());
                                                                        Long lValueOf6 = Long.valueOf(term.getId());
                                                                        int i62 = EditTermImagePreviewActivity.t;
                                                                        Intent intent = new Intent(dVar3, (Class<?>) EditTermImagePreviewActivity.class);
                                                                        intent.putExtra("overlayImagePath", definitionImageLargeUrl);
                                                                        intent.putExtra("termLocalId", lValueOf5);
                                                                        intent.putExtra("termId", lValueOf6);
                                                                        dVar3.startActivityForResult(intent, 1000);
                                                                        dVar3.overridePendingTransition(R.anim.fade_in, R.anim.fade_out_invisible);
                                                                        break;
                                                                    }
                                                                }
                                                                break;
                                                            case 3:
                                                                mVar.h().requestFocus();
                                                                break;
                                                            default:
                                                                mVar.f().requestFocus();
                                                                break;
                                                        }
                                                    }
                                                });
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(itemView.getResources().getResourceName(i)));
    }

    public final void c(float f, boolean z, boolean z2) {
        m = e().getWidth();
        float f2 = f * (-1.0f);
        boolean z3 = !z || (z2 && f2 > DefinitionKt.NO_Float_VALUE);
        if (!z3 && z2 && f2 == DefinitionKt.NO_Float_VALUE) {
            z3 = this.e == 1;
        }
        if (z3) {
            C1043d0 c1043d0A = V.a(g());
            c1043d0A.c(d(false));
            AccelerateDecelerateInterpolator accelerateDecelerateInterpolator = new AccelerateDecelerateInterpolator();
            WeakReference weakReference = c1043d0A.a;
            View view = (View) weakReference.get();
            if (view != null) {
                view.animate().setInterpolator(accelerateDecelerateInterpolator);
            }
            float f3 = l;
            View view2 = (View) weakReference.get();
            if (view2 != null) {
                view2.animate().x(f3);
            }
            q qVar = new q(this, 20);
            View view3 = (View) weakReference.get();
            if (view3 != null) {
                view3.animate().withEndAction(qVar);
            }
            View view4 = (View) weakReference.get();
            if (view4 != null) {
                view4.animate().start();
            }
            e().setEnabled(false);
            this.e = 0;
            return;
        }
        e().setVisibility(0);
        e().setEnabled(true);
        this.e = f2 > DefinitionKt.NO_Float_VALUE ? 1 : f2 < DefinitionKt.NO_Float_VALUE ? -1 : this.e;
        if (!z2) {
            LinearLayout linearLayoutG = g();
            linearLayoutG.setX(Math.min(l, Math.max((-1) * m, linearLayoutG.getX() + f2)));
            return;
        }
        C1043d0 c1043d0A2 = V.a(g());
        c1043d0A2.c(d(true));
        AccelerateDecelerateInterpolator accelerateDecelerateInterpolator2 = new AccelerateDecelerateInterpolator();
        WeakReference weakReference2 = c1043d0A2.a;
        View view5 = (View) weakReference2.get();
        if (view5 != null) {
            view5.animate().setInterpolator(accelerateDecelerateInterpolator2);
        }
        float f4 = m * (-1);
        View view6 = (View) weakReference2.get();
        if (view6 != null) {
            view6.animate().x(f4);
        }
        View view7 = (View) weakReference2.get();
        if (view7 != null) {
            view7.animate().start();
        }
        this.e = 0;
    }

    public final long d(boolean z) {
        float fAbs = Math.abs((l - g().getX()) / (l + m));
        if (z) {
            fAbs = 1 - fAbs;
        }
        return (long) (com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR * fAbs);
    }

    public final LinearLayout e() {
        LinearLayout editSetHiddenButtonPanel = (LinearLayout) this.a.g;
        Intrinsics.checkNotNullExpressionValue(editSetHiddenButtonPanel, "editSetHiddenButtonPanel");
        return editSetHiddenButtonPanel;
    }

    public final QRichFormField f() {
        QRichFormField editSetDefinitionField = (QRichFormField) this.a.e;
        Intrinsics.checkNotNullExpressionValue(editSetDefinitionField, "editSetDefinitionField");
        return editSetDefinitionField;
    }

    public final LinearLayout g() {
        LinearLayout editSetEditTermCard = (LinearLayout) this.a.f;
        Intrinsics.checkNotNullExpressionValue(editSetEditTermCard, "editSetEditTermCard");
        return editSetEditTermCard;
    }

    public final QRichFormField h() {
        QRichFormField editSetWordField = (QRichFormField) this.a.h;
        Intrinsics.checkNotNullExpressionValue(editSetWordField, "editSetWordField");
        return editSetWordField;
    }
}
