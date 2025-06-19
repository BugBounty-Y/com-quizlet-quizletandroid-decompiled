package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3116c6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.pubmatic.sdk.video.c;
import com.quizlet.assembly.widgets.toggle.AssemblyToggleSwitch;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.generated.enums.O1;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4601e;
import com.quizlet.uicommon.ui.common.dialogs.e;
import io.reactivex.rxjava3.subjects.r;
import java.lang.ref.WeakReference;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class h extends com.quizlet.baseui.base.f implements com.quizlet.quizletandroid.ui.setcreation.managers.g {
    public com.quizlet.quizletandroid.sessionhelpers.a l;
    public DatabaseHelper m;
    public com.quizlet.quizletandroid.util.f n;
    public com.quizlet.infra.legacysyncengine.managers.i o;
    public com.quizlet.quizletandroid.ui.setcreation.managers.i p;
    public androidx.work.impl.model.c q;
    public DBStudySet r;
    public List s;
    public boolean t;

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "EditSetDetailsActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final FrameLayout J() {
        return (FrameLayout) ((C4601e) this.k).b.d;
    }

    @Override // com.quizlet.baseui.base.f
    public final com.google.android.material.tabs.l L() {
        return (QTabLayout) ((C4601e) this.k).b.c;
    }

    @Override // com.quizlet.baseui.base.f
    public final Toolbar M() {
        return (Toolbar) ((C4601e) this.k).b.f;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_edit_set_details, (ViewGroup) null, false);
        int i = R.id.appbar;
        View viewC = AbstractC3375o2.c(R.id.appbar, viewInflate);
        if (viewC != null) {
            com.quizlet.features.infra.legacyadapter.databinding.h hVarA = com.quizlet.features.infra.legacyadapter.databinding.h.a(viewC);
            i = R.id.auto_suggest_toggle;
            AssemblyToggleSwitch assemblyToggleSwitch = (AssemblyToggleSwitch) AbstractC3375o2.c(R.id.auto_suggest_toggle, viewInflate);
            if (assemblyToggleSwitch != null) {
                i = R.id.edit_set_details_auto_suggest_label;
                if (((QTextView) AbstractC3375o2.c(R.id.edit_set_details_auto_suggest_label, viewInflate)) != null) {
                    i = R.id.edit_set_details_auto_suggest_section;
                    if (((LinearLayout) AbstractC3375o2.c(R.id.edit_set_details_auto_suggest_section, viewInflate)) != null) {
                        i = R.id.edit_set_details_def_editable_label;
                        if (((QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_editable_label, viewInflate)) != null) {
                            i = R.id.edit_set_details_def_editable_section;
                            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_details_def_editable_section, viewInflate);
                            if (linearLayout != null) {
                                i = R.id.edit_set_details_def_editable_value;
                                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_editable_value, viewInflate);
                                if (qTextView != null) {
                                    i = R.id.edit_set_details_def_lang_label;
                                    if (((QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_lang_label, viewInflate)) != null) {
                                        i = R.id.edit_set_details_def_lang_section;
                                        LinearLayout linearLayout2 = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_details_def_lang_section, viewInflate);
                                        if (linearLayout2 != null) {
                                            i = R.id.edit_set_details_def_lang_value;
                                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_lang_value, viewInflate);
                                            if (qTextView2 != null) {
                                                i = R.id.edit_set_details_def_visibility_label;
                                                if (((QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_visibility_label, viewInflate)) != null) {
                                                    i = R.id.edit_set_details_def_visibility_section;
                                                    LinearLayout linearLayout3 = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_details_def_visibility_section, viewInflate);
                                                    if (linearLayout3 != null) {
                                                        i = R.id.edit_set_details_def_visibility_value;
                                                        QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.edit_set_details_def_visibility_value, viewInflate);
                                                        if (qTextView3 != null) {
                                                            i = R.id.edit_set_details_delete_button;
                                                            QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.edit_set_details_delete_button, viewInflate);
                                                            if (qTextView4 != null) {
                                                                i = R.id.edit_set_details_word_lang_label;
                                                                if (((QTextView) AbstractC3375o2.c(R.id.edit_set_details_word_lang_label, viewInflate)) != null) {
                                                                    i = R.id.edit_set_details_word_lang_section;
                                                                    LinearLayout linearLayout4 = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_details_word_lang_section, viewInflate);
                                                                    if (linearLayout4 != null) {
                                                                        i = R.id.edit_set_details_word_lang_value;
                                                                        QTextView qTextView5 = (QTextView) AbstractC3375o2.c(R.id.edit_set_details_word_lang_value, viewInflate);
                                                                        if (qTextView5 != null) {
                                                                            i = R.id.edit_set_privacy_box;
                                                                            LinearLayout linearLayout5 = (LinearLayout) AbstractC3375o2.c(R.id.edit_set_privacy_box, viewInflate);
                                                                            if (linearLayout5 != null) {
                                                                                return new C4601e((FrameLayout) viewInflate, hVarA, assemblyToggleSwitch, linearLayout, qTextView, linearLayout2, qTextView2, linearLayout3, qTextView3, qTextView4, linearLayout4, qTextView5, linearLayout5);
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
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void O(DBStudySet dBStudySet) {
        String string = getString(androidx.camera.core.impl.utils.executor.i.a(dBStudySet.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : dBStudySet.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a, true));
        int accessType = dBStudySet.getAccessType();
        boolean passwordEdit = dBStudySet.getPasswordEdit();
        String string2 = getString(androidx.camera.core.impl.utils.executor.i.a(accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a, false));
        ((C4601e) this.k).i.setText(string);
        ((C4601e) this.k).e.setText(string2);
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void b() {
        Intent intent = new Intent();
        intent.putExtra("editSessionTrackerKey", this.l.a);
        setResult(100, intent);
        finish();
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void f(com.quizlet.infra.legacysyncengine.net.request.i iVar) {
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void j(int i, boolean z) {
        AbstractC3116c6.h(i, getSupportFragmentManager());
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.managers.g
    public final void k(boolean z) {
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        String stringExtra;
        super.onActivityResult(i, i2, intent);
        if (i == 4321 || i == 1234) {
            if (i2 == 4321 && (stringExtra = intent.getStringExtra("editSetLanguageCodeResult")) != null) {
                this.l.e("language");
                r rVar = this.p.o;
                f fVar = new f(this, 3);
                rVar.getClass();
                new io.reactivex.rxjava3.internal.operators.single.d(rVar, fVar, 1).i(new c(this, i, stringExtra, 2), new com.quizlet.billing.subscriptions.c(2));
            }
        } else if (i == 10000) {
            r rVar2 = this.p.o;
            f fVar2 = new f(this, 2);
            rVar2.getClass();
            new io.reactivex.rxjava3.internal.operators.single.d(rVar2, fVar2, 1).i(new c(this, i2, intent, 1), new com.quizlet.billing.subscriptions.c(2));
        }
        this.l.c(i, i2, intent);
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        Intent intent = new Intent();
        intent.putExtra("autoSuggest", this.t);
        intent.putExtra("editSessionTrackerKey", this.l.a);
        setResult(-1, intent);
        super.onBackPressed();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.a(this);
        AbstractC3188k6.a(((C4601e) this.k).a);
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.p;
        iVar.getClass();
        iVar.p = new WeakReference(this);
        getLifecycle().a(this.p);
        this.p.c(bundle);
        this.l = new com.quizlet.quizletandroid.sessionhelpers.a("NEW", getIntent());
        getLifecycle().a(this.l);
        this.l.h(bundle);
        final int i = 0;
        ((C4601e) this.k).k.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.activities.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                h context = this.b;
                switch (i) {
                    case 0:
                        DBStudySet dBStudySet = context.r;
                        if (dBStudySet != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet.getLanguageCode(O1.WORD), true), 1234);
                            break;
                        }
                        break;
                    case 1:
                        DBStudySet dBStudySet2 = context.r;
                        if (dBStudySet2 != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet2.getLanguageCode(O1.DEFINITION), false), 4321);
                            break;
                        }
                        break;
                    case 2:
                        DBStudySet dBStudySet3 = context.r;
                        if (dBStudySet3 != null) {
                            int iOrdinal = (dBStudySet3.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : context.r.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse = context.r.getPasswordUse();
                            String str = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent.putExtra("current_permission_access", iOrdinal);
                            intent.putExtra("changing_set_visibility", true);
                            intent.putExtra("hasPasswordAlready", passwordUse);
                            context.startActivityForResult(intent, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    case 3:
                        DBStudySet dBStudySet4 = context.r;
                        if (dBStudySet4 != null) {
                            int accessType = dBStudySet4.getAccessType();
                            boolean passwordEdit = context.r.getPasswordEdit();
                            int iOrdinal2 = (accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse2 = context.r.getPasswordUse();
                            String str2 = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent2 = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent2.putExtra("current_permission_access", iOrdinal2);
                            intent2.putExtra("changing_set_visibility", false);
                            intent2.putExtra("hasPasswordAlready", passwordUse2);
                            context.startActivityForResult(intent2, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    default:
                        if (context.r != null) {
                            com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(context, 14);
                            e.a aVar = new e.a(context);
                            aVar.c(R.string.delete_set_confirmation);
                            aVar.e(R.string.yes_dialog_button, bVar);
                            aVar.d(R.string.no_dialog_button, bVar);
                            aVar.g();
                            break;
                        }
                        break;
                }
            }
        });
        final int i2 = 1;
        ((C4601e) this.k).f.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.activities.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                h context = this.b;
                switch (i2) {
                    case 0:
                        DBStudySet dBStudySet = context.r;
                        if (dBStudySet != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet.getLanguageCode(O1.WORD), true), 1234);
                            break;
                        }
                        break;
                    case 1:
                        DBStudySet dBStudySet2 = context.r;
                        if (dBStudySet2 != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet2.getLanguageCode(O1.DEFINITION), false), 4321);
                            break;
                        }
                        break;
                    case 2:
                        DBStudySet dBStudySet3 = context.r;
                        if (dBStudySet3 != null) {
                            int iOrdinal = (dBStudySet3.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : context.r.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse = context.r.getPasswordUse();
                            String str = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent.putExtra("current_permission_access", iOrdinal);
                            intent.putExtra("changing_set_visibility", true);
                            intent.putExtra("hasPasswordAlready", passwordUse);
                            context.startActivityForResult(intent, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    case 3:
                        DBStudySet dBStudySet4 = context.r;
                        if (dBStudySet4 != null) {
                            int accessType = dBStudySet4.getAccessType();
                            boolean passwordEdit = context.r.getPasswordEdit();
                            int iOrdinal2 = (accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse2 = context.r.getPasswordUse();
                            String str2 = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent2 = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent2.putExtra("current_permission_access", iOrdinal2);
                            intent2.putExtra("changing_set_visibility", false);
                            intent2.putExtra("hasPasswordAlready", passwordUse2);
                            context.startActivityForResult(intent2, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    default:
                        if (context.r != null) {
                            com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(context, 14);
                            e.a aVar = new e.a(context);
                            aVar.c(R.string.delete_set_confirmation);
                            aVar.e(R.string.yes_dialog_button, bVar);
                            aVar.d(R.string.no_dialog_button, bVar);
                            aVar.g();
                            break;
                        }
                        break;
                }
            }
        });
        final int i3 = 2;
        ((C4601e) this.k).h.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.activities.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                h context = this.b;
                switch (i3) {
                    case 0:
                        DBStudySet dBStudySet = context.r;
                        if (dBStudySet != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet.getLanguageCode(O1.WORD), true), 1234);
                            break;
                        }
                        break;
                    case 1:
                        DBStudySet dBStudySet2 = context.r;
                        if (dBStudySet2 != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet2.getLanguageCode(O1.DEFINITION), false), 4321);
                            break;
                        }
                        break;
                    case 2:
                        DBStudySet dBStudySet3 = context.r;
                        if (dBStudySet3 != null) {
                            int iOrdinal = (dBStudySet3.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : context.r.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse = context.r.getPasswordUse();
                            String str = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent.putExtra("current_permission_access", iOrdinal);
                            intent.putExtra("changing_set_visibility", true);
                            intent.putExtra("hasPasswordAlready", passwordUse);
                            context.startActivityForResult(intent, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    case 3:
                        DBStudySet dBStudySet4 = context.r;
                        if (dBStudySet4 != null) {
                            int accessType = dBStudySet4.getAccessType();
                            boolean passwordEdit = context.r.getPasswordEdit();
                            int iOrdinal2 = (accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse2 = context.r.getPasswordUse();
                            String str2 = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent2 = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent2.putExtra("current_permission_access", iOrdinal2);
                            intent2.putExtra("changing_set_visibility", false);
                            intent2.putExtra("hasPasswordAlready", passwordUse2);
                            context.startActivityForResult(intent2, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    default:
                        if (context.r != null) {
                            com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(context, 14);
                            e.a aVar = new e.a(context);
                            aVar.c(R.string.delete_set_confirmation);
                            aVar.e(R.string.yes_dialog_button, bVar);
                            aVar.d(R.string.no_dialog_button, bVar);
                            aVar.g();
                            break;
                        }
                        break;
                }
            }
        });
        final int i4 = 3;
        ((C4601e) this.k).d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.activities.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                h context = this.b;
                switch (i4) {
                    case 0:
                        DBStudySet dBStudySet = context.r;
                        if (dBStudySet != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet.getLanguageCode(O1.WORD), true), 1234);
                            break;
                        }
                        break;
                    case 1:
                        DBStudySet dBStudySet2 = context.r;
                        if (dBStudySet2 != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet2.getLanguageCode(O1.DEFINITION), false), 4321);
                            break;
                        }
                        break;
                    case 2:
                        DBStudySet dBStudySet3 = context.r;
                        if (dBStudySet3 != null) {
                            int iOrdinal = (dBStudySet3.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : context.r.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse = context.r.getPasswordUse();
                            String str = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent.putExtra("current_permission_access", iOrdinal);
                            intent.putExtra("changing_set_visibility", true);
                            intent.putExtra("hasPasswordAlready", passwordUse);
                            context.startActivityForResult(intent, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    case 3:
                        DBStudySet dBStudySet4 = context.r;
                        if (dBStudySet4 != null) {
                            int accessType = dBStudySet4.getAccessType();
                            boolean passwordEdit = context.r.getPasswordEdit();
                            int iOrdinal2 = (accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse2 = context.r.getPasswordUse();
                            String str2 = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent2 = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent2.putExtra("current_permission_access", iOrdinal2);
                            intent2.putExtra("changing_set_visibility", false);
                            intent2.putExtra("hasPasswordAlready", passwordUse2);
                            context.startActivityForResult(intent2, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    default:
                        if (context.r != null) {
                            com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(context, 14);
                            e.a aVar = new e.a(context);
                            aVar.c(R.string.delete_set_confirmation);
                            aVar.e(R.string.yes_dialog_button, bVar);
                            aVar.d(R.string.no_dialog_button, bVar);
                            aVar.g();
                            break;
                        }
                        break;
                }
            }
        });
        final int i5 = 4;
        ((C4601e) this.k).j.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.setcreation.activities.g
            public final /* synthetic */ h b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                h context = this.b;
                switch (i5) {
                    case 0:
                        DBStudySet dBStudySet = context.r;
                        if (dBStudySet != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet.getLanguageCode(O1.WORD), true), 1234);
                            break;
                        }
                        break;
                    case 1:
                        DBStudySet dBStudySet2 = context.r;
                        if (dBStudySet2 != null) {
                            context.startActivityForResult(EditSetLanguageSelectionActivity.Q(context, dBStudySet2.getLanguageCode(O1.DEFINITION), false), 4321);
                            break;
                        }
                        break;
                    case 2:
                        DBStudySet dBStudySet3 = context.r;
                        if (dBStudySet3 != null) {
                            int iOrdinal = (dBStudySet3.getAccessType() == 2 ? com.quizlet.quizletandroid.util.j.c : context.r.getPasswordUse() ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse = context.r.getPasswordUse();
                            String str = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent.putExtra("current_permission_access", iOrdinal);
                            intent.putExtra("changing_set_visibility", true);
                            intent.putExtra("hasPasswordAlready", passwordUse);
                            context.startActivityForResult(intent, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    case 3:
                        DBStudySet dBStudySet4 = context.r;
                        if (dBStudySet4 != null) {
                            int accessType = dBStudySet4.getAccessType();
                            boolean passwordEdit = context.r.getPasswordEdit();
                            int iOrdinal2 = (accessType == 2 ? passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a : passwordEdit ? com.quizlet.quizletandroid.util.j.b : com.quizlet.quizletandroid.util.j.a).ordinal();
                            boolean passwordUse2 = context.r.getPasswordUse();
                            String str2 = EditSetPermissionSelectionActivity.v;
                            Intrinsics.checkNotNullParameter(context, "context");
                            Intent intent2 = new Intent(context, (Class<?>) EditSetPermissionSelectionActivity.class);
                            intent2.putExtra("current_permission_access", iOrdinal2);
                            intent2.putExtra("changing_set_visibility", false);
                            intent2.putExtra("hasPasswordAlready", passwordUse2);
                            context.startActivityForResult(intent2, c.a.DEFAULT_MEDIA_URI_TIMEOUT);
                            break;
                        }
                        break;
                    default:
                        if (context.r != null) {
                            com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(context, 14);
                            e.a aVar = new e.a(context);
                            aVar.c(R.string.delete_set_confirmation);
                            aVar.e(R.string.yes_dialog_button, bVar);
                            aVar.d(R.string.no_dialog_button, bVar);
                            aVar.g();
                            break;
                        }
                        break;
                }
            }
        });
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) throws Resources.NotFoundException {
        super.onPostCreate(bundle);
        setTitle(R.string.edit_set_options_toolbar_title);
        this.l.e("tab_info");
        boolean booleanExtra = getIntent().getBooleanExtra("autoSuggest", false);
        this.t = booleanExtra;
        AssemblyToggleSwitch assemblyToggleSwitch = ((C4601e) this.k).c;
        assemblyToggleSwitch.setChecked(booleanExtra);
        assemblyToggleSwitch.setOnCheckedChangeListener(new com.google.android.material.chip.a(this, 3));
        new io.reactivex.rxjava3.internal.operators.single.d(this.q.u(), new f(this, 4), 1).i(new f(this, 5), io.reactivex.rxjava3.internal.functions.d.e);
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        r rVar = this.p.q;
        f fVar = new f(this, 6);
        rVar.getClass();
        io.reactivex.rxjava3.internal.operators.single.d dVar = new io.reactivex.rxjava3.internal.operators.single.d(rVar, fVar, 1);
        f fVar2 = new f(this, 7);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.e;
        dVar.i(fVar2, gVar);
        r rVar2 = this.p.o;
        f fVar3 = new f(this, 0);
        rVar2.getClass();
        new io.reactivex.rxjava3.internal.operators.single.d(rVar2, fVar3, 1).i(new f(this, 1), gVar);
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = this.p;
        bundle.putLong("editSetActivityId", iVar.k.longValue());
        bundle.putBoolean("editSetActivityIsCopySetFlow", iVar.l);
        bundle.putParcelable("editSessionTrackerKey", this.l.a);
    }
}
