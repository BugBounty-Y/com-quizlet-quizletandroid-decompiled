package com.quizlet.uicommon.ui.common.dialogs;

import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.app.D;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.adapter.ViewOnClickListenerC4055k;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QCheckBox;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.util.HashMap;
import java.util.LinkedHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class e extends D {
    public static final /* synthetic */ int s = 0;
    public final float f;
    public QTextView g;
    public RelativeLayout h;
    public QTextView i;
    public RelativeLayout j;
    public QButton k;
    public QButton l;
    public FrameLayout m;
    public LinearLayout n;
    public LinearLayout o;
    public com.quizlet.quizletandroid.ui.common.databinding.c p;
    public a q;
    public HashMap r;

    public static class a {
        public final Context a;
        public boolean b = true;
        public DialogInterface.OnCancelListener c;
        public String d;
        public CharSequence e;
        public LinkedHashMap f;
        public HashMap g;
        public View h;
        public String i;
        public f j;
        public String k;
        public f l;

        public a(Context context) {
            this.a = context;
        }

        public final void a(d dVar, com.quizlet.features.setpage.utils.setpermissions.b bVar) {
            if (this.f == null) {
                this.f = new LinkedHashMap();
            }
            this.f.put(0, dVar);
            if (bVar != null) {
                if (this.g == null) {
                    this.g = new HashMap();
                }
                this.g.put(0, bVar);
            }
        }

        public final e b() {
            e eVar = new e(this.a);
            eVar.q = this;
            return eVar;
        }

        public final void c(int i) {
            this.e = this.a.getString(i);
        }

        public final void d(int i, f fVar) {
            this.k = this.a.getString(i);
            this.l = fVar;
        }

        public final void e(int i, f fVar) {
            this.i = this.a.getString(i);
            this.j = fVar;
        }

        public final void f(int i) {
            this.d = this.a.getString(i);
        }

        public final void g() {
            b().show();
        }
    }

    public e(Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.f = TypedValue.applyDimension(1, 600.0f, context.getResources().getDisplayMetrics());
    }

    public static boolean g(TextView textView, CharSequence charSequence) {
        boolean zIsEmpty = TextUtils.isEmpty(charSequence);
        boolean z = !zIsEmpty;
        textView.setVisibility(!zIsEmpty ? 0 : 8);
        textView.setText(charSequence);
        return z;
    }

    public final EditText f(int i) {
        HashMap map = this.r;
        if (map == null) {
            return null;
        }
        return ((QFormField) map.get(Integer.valueOf(i))).getEditText();
    }

    @Override // androidx.appcompat.app.D, androidx.activity.u, android.app.Dialog
    public void onCreate(Bundle bundle) {
        boolean z;
        super.onCreate(bundle);
        int i = 1;
        c().g(1);
        Window window = getWindow();
        int i2 = 0;
        if (window != null) {
            window.getDecorView().setBackgroundColor(com.quizlet.themes.extensions.a.a(getContext(), R.attr.SysColorCard));
            window.getWindowManager().getDefaultDisplay().getMetrics(new DisplayMetrics());
            window.getAttributes().width = Math.round(Math.min(this.f, Math.min(r5.widthPixels, r5.heightPixels) * 0.9f));
            View viewInflate = LayoutInflater.from(getContext()).inflate(R.layout.dialog_qalert, (ViewGroup) null, false);
            int i3 = R.id.qalert_button_wrapper;
            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.qalert_button_wrapper, viewInflate);
            if (relativeLayout != null) {
                i3 = R.id.qalert_checkbox;
                QCheckBox qCheckBox = (QCheckBox) AbstractC3375o2.c(R.id.qalert_checkbox, viewInflate);
                if (qCheckBox != null) {
                    i3 = R.id.qalert_checkbox_text;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.qalert_checkbox_text, viewInflate);
                    if (qTextView != null) {
                        i3 = R.id.qalert_checkbox_wrapper;
                        LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.qalert_checkbox_wrapper, viewInflate);
                        if (linearLayout != null) {
                            i3 = R.id.qalert_content_wrapper;
                            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.qalert_content_wrapper, viewInflate);
                            if (frameLayout != null) {
                                i3 = R.id.qalert_custom;
                                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.qalert_custom, viewInflate);
                                if (frameLayout2 != null) {
                                    i3 = R.id.qalert_default_content_wrapper;
                                    RelativeLayout relativeLayout2 = (RelativeLayout) AbstractC3375o2.c(R.id.qalert_default_content_wrapper, viewInflate);
                                    if (relativeLayout2 != null) {
                                        i3 = R.id.qalert_edittext_wrapper;
                                        LinearLayout linearLayout2 = (LinearLayout) AbstractC3375o2.c(R.id.qalert_edittext_wrapper, viewInflate);
                                        if (linearLayout2 != null) {
                                            i3 = R.id.qalert_listview;
                                            ListView listView = (ListView) AbstractC3375o2.c(R.id.qalert_listview, viewInflate);
                                            if (listView != null) {
                                                i3 = R.id.qalert_listview_action_icon;
                                                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.qalert_listview_action_icon, viewInflate);
                                                if (imageView != null) {
                                                    i3 = R.id.qalert_listview_action_separator;
                                                    View viewC = AbstractC3375o2.c(R.id.qalert_listview_action_separator, viewInflate);
                                                    if (viewC != null) {
                                                        i3 = R.id.qalert_listview_action_text;
                                                        QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.qalert_listview_action_text, viewInflate);
                                                        if (qTextView2 != null) {
                                                            i3 = R.id.qalert_listview_action_wrapper;
                                                            RelativeLayout relativeLayout3 = (RelativeLayout) AbstractC3375o2.c(R.id.qalert_listview_action_wrapper, viewInflate);
                                                            if (relativeLayout3 != null) {
                                                                i3 = R.id.qalert_listview_wrapper;
                                                                LinearLayout linearLayout3 = (LinearLayout) AbstractC3375o2.c(R.id.qalert_listview_wrapper, viewInflate);
                                                                if (linearLayout3 != null) {
                                                                    i3 = R.id.qalert_message;
                                                                    QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.qalert_message, viewInflate);
                                                                    if (qTextView3 != null) {
                                                                        i3 = R.id.qalert_negative_button;
                                                                        QButton qButton = (QButton) AbstractC3375o2.c(R.id.qalert_negative_button, viewInflate);
                                                                        if (qButton != null) {
                                                                            i3 = R.id.qalert_positive_button;
                                                                            QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.qalert_positive_button, viewInflate);
                                                                            if (qButton2 != null) {
                                                                                i3 = R.id.qalert_title;
                                                                                QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.qalert_title, viewInflate);
                                                                                if (qTextView4 != null) {
                                                                                    LinearLayout linearLayout4 = (LinearLayout) viewInflate;
                                                                                    this.p = new com.quizlet.quizletandroid.ui.common.databinding.c(linearLayout4, relativeLayout, qCheckBox, qTextView, linearLayout, frameLayout, frameLayout2, relativeLayout2, linearLayout2, listView, imageView, viewC, qTextView2, relativeLayout3, linearLayout3, qTextView3, qButton, qButton2, qTextView4);
                                                                                    window.setContentView(linearLayout4);
                                                                                    com.quizlet.quizletandroid.ui.common.databinding.c cVar = this.p;
                                                                                    this.g = cVar.n;
                                                                                    this.h = cVar.f;
                                                                                    this.i = cVar.k;
                                                                                    this.j = cVar.b;
                                                                                    this.k = cVar.m;
                                                                                    this.l = cVar.l;
                                                                                    this.m = cVar.e;
                                                                                    this.n = cVar.g;
                                                                                    this.o = cVar.j;
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
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i3)));
        }
        a aVar = this.q;
        if (aVar == null) {
            return;
        }
        setCancelable(aVar.b);
        setOnCancelListener(this.q.c);
        g(this.g, this.q.d);
        g(this.i, this.q.e);
        LinkedHashMap linkedHashMap = this.q.f;
        if (linkedHashMap != null) {
            for (Integer num : linkedHashMap.keySet()) {
                d dVar = (d) linkedHashMap.get(num);
                int iIntValue = num.intValue();
                dVar.getClass();
                QFormField qFormField = new QFormField(getContext(), iIntValue);
                EditText editText = qFormField.getEditText();
                int i4 = dVar.b;
                if (i4 == 2) {
                    editText.setInputType(129);
                } else if (i4 == 1) {
                    editText.setInputType(16385);
                } else if (i4 == 3) {
                    editText.setSingleLine(true);
                    editText.setInputType(2);
                }
                editText.setText((CharSequence) null);
                editText.setSelection(0);
                editText.setHint(dVar.a);
                this.n.addView(qFormField);
                if (this.r == null) {
                    this.r = new HashMap();
                } else {
                    qFormField.setPadding(0, (int) getContext().getResources().getDimension(R.dimen.dialog_edittext_margin), 0, 0);
                }
                qFormField.setLabel(null);
                this.r.put(num, qFormField);
            }
            HashMap map = this.r;
            if (map != null && map.size() > 0) {
                this.n.setVisibility(0);
                if (getWindow() != null) {
                    getWindow().setSoftInputMode(4);
                }
            }
        }
        this.q.getClass();
        this.m.setVisibility(8);
        this.o.setVisibility(8);
        this.h.setVisibility(0);
        this.q.getClass();
        View view = this.q.h;
        if (view != null) {
            this.h.setVisibility(8);
            this.o.setVisibility(8);
            this.m.setVisibility(0);
            this.m.addView(view);
        }
        QButton qButton3 = this.k;
        a aVar2 = this.q;
        String str = aVar2.i;
        f fVar = aVar2.j;
        if (g(qButton3, str)) {
            qButton3.setOnClickListener(new ViewOnClickListenerC4055k(this, i, fVar, 3));
            z = true;
        } else {
            z = false;
        }
        QButton qButton4 = this.l;
        a aVar3 = this.q;
        String str2 = aVar3.k;
        f fVar2 = aVar3.l;
        if (g(qButton4, str2)) {
            qButton4.setOnClickListener(new ViewOnClickListenerC4055k(this, -1, fVar2, 3));
        } else {
            i = 0;
        }
        RelativeLayout relativeLayout4 = this.j;
        if (!z && i == 0) {
            i2 = 8;
        }
        relativeLayout4.setVisibility(i2);
    }
}
