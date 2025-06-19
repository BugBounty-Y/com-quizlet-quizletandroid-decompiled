package com.quizlet.quizletandroid.ui.setpage.shareset;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ScrollView;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.S5;
import com.quizlet.edgy.databinding.e;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.infra.legacyadapter.databinding.f;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4614s;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;
import com.quizlet.utm.a;
import kotlin.Metadata;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class c extends a<C4614s> {
    public static final String I;
    public long B;
    public String C;
    public String D;
    public com.quizlet.features.infra.basestudy.data.models.shareset.a E;
    public boolean F;
    public com.quizlet.infra.legacysyncengine.managers.d G;
    public EventLogger H;

    static {
        String simpleName = c.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        I = simpleName;
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_share_set, viewGroup, false);
        int i = R.id.headline_emoji;
        AppCompatTextView appCompatTextView = (AppCompatTextView) AbstractC3375o2.c(R.id.headline_emoji, viewInflate);
        if (appCompatTextView != null) {
            i = R.id.share_set_add_to_class_or_folder_button;
            QButton qButton = (QButton) AbstractC3375o2.c(R.id.share_set_add_to_class_or_folder_button, viewInflate);
            if (qButton != null) {
                i = R.id.share_set_button;
                QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.share_set_button, viewInflate);
                if (qButton2 != null) {
                    i = R.id.share_set_message;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.share_set_message, viewInflate);
                    if (qTextView != null) {
                        i = R.id.share_set_whatsapp_add_to_class;
                        View viewC = AbstractC3375o2.c(R.id.share_set_whatsapp_add_to_class, viewInflate);
                        if (viewC != null) {
                            int i2 = R.id.add_to_class;
                            View viewC2 = AbstractC3375o2.c(R.id.add_to_class, viewC);
                            if (viewC2 != null) {
                                if (((ImageView) AbstractC3375o2.c(R.id.add_to_class_icon, viewC2)) == null) {
                                    throw new NullPointerException("Missing required view with ID: ".concat(viewC2.getResources().getResourceName(R.id.add_to_class_icon)));
                                }
                                e eVar = new e((ConstraintLayout) viewC2, 3);
                                i2 = R.id.share_buttons_divider;
                                View viewC3 = AbstractC3375o2.c(R.id.share_buttons_divider, viewC);
                                if (viewC3 != null) {
                                    i2 = R.id.whatsapp_share;
                                    View viewC4 = AbstractC3375o2.c(R.id.whatsapp_share, viewC);
                                    if (viewC4 != null) {
                                        if (((ImageView) AbstractC3375o2.c(R.id.whatsapp_icon, viewC4)) == null) {
                                            throw new NullPointerException("Missing required view with ID: ".concat(viewC4.getResources().getResourceName(R.id.whatsapp_icon)));
                                        }
                                        C4614s c4614s = new C4614s((ScrollView) viewInflate, appCompatTextView, qButton, qButton2, qTextView, new f((ConstraintLayout) viewC, eVar, viewC3, new e((ConstraintLayout) viewC4, 4), 8));
                                        Intrinsics.checkNotNullExpressionValue(c4614s, "inflate(...)");
                                        return c4614s;
                                    }
                                }
                            }
                            throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void U() {
        EventLogger eventLogger = this.H;
        if (eventLogger == null) {
            Intrinsics.m("eventLogger");
            throw null;
        }
        eventLogger.I("add_to_class_click_from_share_set_dialog");
        I iRequireActivity = requireActivity();
        String str = AddSetToClassActivity.s;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        iRequireActivity.startActivityForResult(S5.b(contextRequireContext, A.b(Long.valueOf(this.B))), 216);
        H(false, false);
    }

    public final void V(com.quizlet.features.infra.basestudy.data.models.shareset.a aVar) throws Resources.NotFoundException {
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        long j = this.B;
        String str = this.C;
        String str2 = this.D;
        if (str2 == null) {
            Intrinsics.m("studySetTitle");
            throw null;
        }
        a.c cVar = new a.c(com.quizlet.utm.campaigns.b.SET_CREATION_SHARE, com.quizlet.utm.mediums.b.SHARE_LINK, com.quizlet.utm.sources.b.SHARE_SHEET_ANDROID);
        com.quizlet.infra.legacysyncengine.managers.d dVar = this.G;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        Intent intentB = new com.quizlet.features.setpage.utils.links.b(contextRequireContext, j, str, str2, new a.C0023a(cVar, Long.valueOf(dVar.e.getPersonId())), null, null).b(aVar);
        if (intentB != null) {
            startActivity(intentB);
        }
        H(false, false);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        com.quizlet.features.infra.basestudy.data.models.shareset.a aVarValueOf;
        super.onCreate(bundle);
        Bundle bundleRequireArguments = requireArguments();
        Intrinsics.checkNotNullExpressionValue(bundleRequireArguments, "requireArguments(...)");
        this.B = bundleRequireArguments.getLong("argStudySetId");
        this.D = bundleRequireArguments.getString("argStudySetTitle", "");
        this.C = bundleRequireArguments.getString("argStudySetWebUrl");
        String string = bundleRequireArguments.getString("argShareStatus");
        if (string == null || (aVarValueOf = com.quizlet.features.infra.basestudy.data.models.shareset.a.valueOf(string)) == null) {
            aVarValueOf = com.quizlet.features.infra.basestudy.data.models.shareset.a.d;
        }
        this.E = aVarValueOf;
        this.F = bundleRequireArguments.getBoolean("argDisplayWhatsappShare");
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x001b  */
    @Override // androidx.fragment.app.Fragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onViewCreated(android.view.View r3, android.os.Bundle r4) {
        /*
            r2 = this;
            java.lang.String r0 = "view"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r0)
            super.onViewCreated(r3, r4)
            com.quizlet.infra.legacysyncengine.managers.d r3 = r2.G
            if (r3 == 0) goto Lbf
            com.quizlet.db.data.models.persisted.DBUser r3 = r3.r
            if (r3 == 0) goto L1b
            int r3 = r3.getSelfIdentifiedUserType()
            com.quizlet.features.setpage.shareset.b r4 = com.quizlet.features.setpage.shareset.b.d
            int r0 = r4.a
            if (r3 != r0) goto L1b
            goto L1d
        L1b:
            com.quizlet.features.setpage.shareset.b r4 = com.quizlet.features.setpage.shareset.b.e
        L1d:
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            java.lang.String r0 = r4.b
            androidx.appcompat.widget.AppCompatTextView r3 = r3.b
            r3.setText(r0)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            int r4 = r4.c
            java.lang.String r4 = r2.getString(r4)
            com.quizlet.partskit.widgets.QTextView r3 = r3.e
            r3.setText(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.quizletandroid.ui.setpage.shareset.b r4 = new com.quizlet.quizletandroid.ui.setpage.shareset.b
            r0 = 0
            r4.<init>(r2)
            com.quizlet.partskit.widgets.QButton r3 = r3.d
            r3.setOnClickListener(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.features.infra.legacyadapter.databinding.f r3 = r3.f
            java.lang.Object r3 = r3.e
            com.quizlet.edgy.databinding.e r3 = (com.quizlet.edgy.databinding.e) r3
            androidx.constraintlayout.widget.ConstraintLayout r3 = r3.b
            com.quizlet.quizletandroid.ui.setpage.shareset.b r4 = new com.quizlet.quizletandroid.ui.setpage.shareset.b
            r0 = 1
            r4.<init>(r2)
            r3.setOnClickListener(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.features.infra.legacyadapter.databinding.f r3 = r3.f
            java.lang.Object r3 = r3.b
            com.quizlet.edgy.databinding.e r3 = (com.quizlet.edgy.databinding.e) r3
            androidx.constraintlayout.widget.ConstraintLayout r3 = r3.b
            com.quizlet.quizletandroid.ui.setpage.shareset.b r4 = new com.quizlet.quizletandroid.ui.setpage.shareset.b
            r0 = 2
            r4.<init>(r2)
            r3.setOnClickListener(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.quizletandroid.ui.setpage.shareset.b r4 = new com.quizlet.quizletandroid.ui.setpage.shareset.b
            r0 = 3
            r4.<init>(r2)
            com.quizlet.partskit.widgets.QButton r3 = r3.c
            r3.setOnClickListener(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.partskit.widgets.QButton r3 = r3.c
            java.lang.String r4 = "shareSetAddToClassOrFolderButton"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)
            boolean r4 = r2.F
            r0 = 8
            r1 = 0
            if (r4 != 0) goto La1
            r4 = r1
            goto La2
        La1:
            r4 = r0
        La2:
            r3.setVisibility(r4)
            androidx.viewbinding.a r3 = r2.P()
            com.quizlet.quizletandroid.databinding.s r3 = (com.quizlet.quizletandroid.databinding.C4614s) r3
            com.quizlet.features.infra.legacyadapter.databinding.f r3 = r3.f
            android.view.View r3 = r3.c
            androidx.constraintlayout.widget.ConstraintLayout r3 = (androidx.constraintlayout.widget.ConstraintLayout) r3
            java.lang.String r4 = "getRoot(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)
            boolean r4 = r2.F
            if (r4 == 0) goto Lbb
            r0 = r1
        Lbb:
            r3.setVisibility(r0)
            return
        Lbf:
            java.lang.String r3 = "loggedInUserManager"
            kotlin.jvm.internal.Intrinsics.m(r3)
            r3 = 0
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setpage.shareset.c.onViewCreated(android.view.View, android.os.Bundle):void");
    }
}
