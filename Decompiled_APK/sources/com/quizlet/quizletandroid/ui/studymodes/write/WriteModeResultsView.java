package com.quizlet.quizletandroid.ui.studymodes.write;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.RelativeLayout;
import androidx.collection.C0219q;
import androidx.legacy.widget.Space;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.views.ArcProgressLayout;
import java.util.HashMap;

/* loaded from: classes3.dex */
public class WriteModeResultsView extends LinearLayout {
    public static final /* synthetic */ int q = 0;
    public final com.quizlet.quizletandroid.ui.common.adapter.e a;
    public com.quizlet.quizletandroid.ui.common.adapter.presenter.e b;
    public com.quizlet.infra.legacysyncengine.managers.d c;
    public com.quizlet.infra.legacysyncengine.net.f d;
    public com.quizlet.quizletandroid.managers.audio.h e;
    public io.ktor.client.plugins.api.d f;
    public l g;
    public com.quizlet.data.repository.folderwithcreator.e h;
    public com.quizlet.assembly.databinding.b i;
    public final k j;
    public final k k;
    public HashMap l;
    public HashMap m;
    public com.google.common.collect.j n;
    public C0219q o;
    public com.commonsware.cwac.merge.c p;

    public WriteModeResultsView(Context context) {
        super(context);
        this.a = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(6);
        this.j = new k(this, 0);
        this.k = new k(this, 1);
        a(context);
    }

    public final void a(Context context) {
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.c = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
        this.d = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
        this.e = (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get();
        this.f = uVar.g();
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.write_results, (ViewGroup) null, false);
        ListView listView = (ListView) AbstractC3375o2.c(R.id.write_results_listview, viewInflate);
        if (listView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.write_results_listview)));
        }
        RelativeLayout relativeLayout = (RelativeLayout) viewInflate;
        this.i = new com.quizlet.assembly.databinding.b(3, listView, relativeLayout);
        addView(relativeLayout);
        View viewInflate2 = LayoutInflater.from(context).inflate(R.layout.write_results_header, (ViewGroup) null, false);
        int i = R.id.learn_restart_button_space;
        Space space = (Space) AbstractC3375o2.c(R.id.learn_restart_button_space, viewInflate2);
        if (space != null) {
            i = R.id.learn_results_arc_view;
            ArcProgressLayout arcProgressLayout = (ArcProgressLayout) AbstractC3375o2.c(R.id.learn_results_arc_view, viewInflate2);
            if (arcProgressLayout != null) {
                i = R.id.learn_results_message;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.learn_results_message, viewInflate2);
                if (qTextView != null) {
                    i = R.id.learn_results_restart;
                    QButton qButton = (QButton) AbstractC3375o2.c(R.id.learn_results_restart, viewInflate2);
                    if (qButton != null) {
                        i = R.id.learn_results_restart_selected;
                        QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.learn_results_restart_selected, viewInflate2);
                        if (qButton2 != null) {
                            this.h = new com.quizlet.data.repository.folderwithcreator.e(this, new com.quizlet.explanations.databinding.n((LinearLayout) viewInflate2, space, arcProgressLayout, qTextView, qButton, qButton2));
                            com.commonsware.cwac.merge.c cVar = new com.commonsware.cwac.merge.c();
                            this.p = cVar;
                            ((ListView) this.i.c).setAdapter((ListAdapter) cVar);
                            this.b = new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(this.c, this.d, this.e, this.a, this.f);
                            return;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate2.getResources().getResourceName(i)));
    }

    public void setDelegate(l lVar) {
        this.g = lVar;
    }

    public WriteModeResultsView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.a = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(6);
        this.j = new k(this, 0);
        this.k = new k(this, 1);
        a(context);
    }
}
