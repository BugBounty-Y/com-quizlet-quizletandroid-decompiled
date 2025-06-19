package com.quizlet.quizletandroid.ui.studymodes.write;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import java.util.ArrayList;

/* loaded from: classes3.dex */
public class WriteModeCheckPointView extends LinearLayout {
    public static final /* synthetic */ int n = 0;
    public final com.quizlet.quizletandroid.ui.common.adapter.presenter.e a;
    public final ListView b;
    public final com.quizlet.infra.legacysyncengine.managers.d c;
    public final com.quizlet.infra.legacysyncengine.net.f d;
    public final com.quizlet.quizletandroid.managers.audio.h e;
    public final io.ktor.client.plugins.api.d f;
    public com.quizlet.quizletandroid.ui.common.adapter.b g;
    public com.quizlet.quizletandroid.ui.common.adapter.b h;
    public final com.quizlet.data.repository.explanations.myexplanations.a i;
    public e j;
    public ArrayList k;
    public ArrayList l;
    public com.commonsware.cwac.merge.c m;

    public WriteModeCheckPointView(Context context) {
        this(context, null);
    }

    public void setCheckPointListener(e eVar) {
        this.j = eVar;
    }

    public WriteModeCheckPointView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        com.quizlet.quizletandroid.ui.setcreation.imageupload.a aVar = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(5);
        u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
        this.c = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
        this.d = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
        this.e = (com.quizlet.quizletandroid.managers.audio.h) uVar.f0.get();
        this.f = uVar.g();
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.write_checkpoint, (ViewGroup) this, false);
        addView(viewInflate);
        ListView listView = (ListView) AbstractC3375o2.c(R.id.write_checkpoint_listview, viewInflate);
        if (listView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.write_checkpoint_listview)));
        }
        this.b = listView;
        this.a = new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(this.c, this.d, this.e, aVar, this.f);
        View viewInflate2 = LayoutInflater.from(context).inflate(R.layout.write_checkpoint_header, (ViewGroup) null, false);
        int i = R.id.learn_checkpoint_nextbutton;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.learn_checkpoint_nextbutton, viewInflate2);
        if (qButton != null) {
            i = R.id.learn_overall_progress_view;
            ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.learn_overall_progress_view, viewInflate2);
            if (progressBar != null) {
                this.i = new com.quizlet.data.repository.explanations.myexplanations.a(this, new com.onetrust.otpublishers.headless.databinding.b((LinearLayout) viewInflate2, qButton, progressBar, 6));
                this.m = new com.commonsware.cwac.merge.c();
                return;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate2.getResources().getResourceName(i)));
    }
}
