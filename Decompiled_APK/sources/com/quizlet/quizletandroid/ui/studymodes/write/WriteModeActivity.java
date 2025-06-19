package com.quizlet.quizletandroid.ui.studymodes.write;

import android.animation.LayoutTransition;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.activity.v;
import androidx.appcompat.widget.Toolbar;
import androidx.collection.C0219q;
import androidx.core.view.L;
import androidx.lifecycle.y0;
import com.braze.Braze;
import com.braze.models.outgoing.BrazeProperties;
import com.bumptech.glide.Glide;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.facebook.login.E;
import com.facebook.z;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3525r4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3543u4;
import com.google.common.collect.C3919b;
import com.google.common.collect.C3922e;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBAnswer;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.eventlogger.model.QuestionEventLog;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.EnumC4509p;
import com.quizlet.generated.enums.EnumC4520t;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import com.quizlet.generated.enums.r;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.quizletandroid.C4595c;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4608l;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.common.views.ArcProgressLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.WeakHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.q;

@SuppressLint({"UseSparseArrays"})
/* loaded from: classes3.dex */
public class WriteModeActivity extends com.quizlet.features.write.base.b implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a, e, j, com.quizlet.quizletandroid.ui.common.dialogs.b, l {
    public static final /* synthetic */ int z1 = 0;
    public final io.reactivex.rxjava3.disposables.a K;
    public List L;
    public ArrayList M;
    public ArrayList V;
    public ArrayList W;
    public ArrayList X;
    public DBTerm Y;
    public HashMap Z;
    public HashMap c1;
    public int d1;
    public int e1;
    public int f1;
    public String g1;
    public Long h1;
    public com.quizlet.quizletandroid.managers.audio.h i1;
    public com.quizlet.infra.legacysyncengine.net.f j1;
    public com.quizlet.infra.legacysyncengine.net.c k1;
    public com.quizlet.infra.legacysyncengine.managers.i l1;
    public com.quizlet.qutils.image.loading.a m1;
    public C4595c n1;
    public com.features.flashcards.creatormarketing.h o1;
    public com.quizlet.features.infra.basestudy.manager.d p1;
    public com.quizlet.data.repository.widget.b q1;
    public grading.a r1;
    public ExecutionRouter s1;
    public androidx.work.impl.background.greedy.d t1;
    public Boolean u1;
    public com.quizlet.login.authentication.login.a v1;
    public volatile dagger.hilt.android.internal.managers.b w1;
    public final Object x1;
    public boolean y1;

    public WriteModeActivity() {
        this.w = new io.reactivex.rxjava3.disposables.a();
        this.J = new io.reactivex.rxjava3.subjects.b();
        this.K = new io.reactivex.rxjava3.disposables.a();
        this.g1 = null;
        this.h1 = null;
        this.u1 = Boolean.FALSE;
        this.x1 = new Object();
        this.y1 = false;
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 28));
    }

    public static Intent T(Context context, Integer num, Long l, String str, Long l2, G1 g1, boolean z) {
        Intent intent = new Intent(context, (Class<?>) WriteModeActivity.class);
        intent.putExtra("navigationSource", num);
        intent.putExtra("studyableModelId", l);
        intent.putExtra("studyableModelTitle", str);
        intent.putExtra("studyableModelLocalId", l2);
        intent.putExtra("studyableModelType", g1.b());
        intent.putExtra("selectedOnlyIntent", z);
        intent.setAction(l + "_" + l2 + "_" + g1.b() + "_" + z);
        return intent;
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "WriteModeActivity";
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.activity_write_mode, (ViewGroup) null, false);
        int i = R.id.content_frame;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.content_frame, viewInflate);
        if (frameLayout != null) {
            i = R.id.learn_checkpointview;
            WriteModeCheckPointView writeModeCheckPointView = (WriteModeCheckPointView) AbstractC3375o2.c(R.id.learn_checkpointview, viewInflate);
            if (writeModeCheckPointView != null) {
                i = R.id.learn_promptview;
                WriteModePromptView writeModePromptView = (WriteModePromptView) AbstractC3375o2.c(R.id.learn_promptview, viewInflate);
                if (writeModePromptView != null) {
                    i = R.id.learn_resultsview;
                    WriteModeResultsView writeModeResultsView = (WriteModeResultsView) AbstractC3375o2.c(R.id.learn_resultsview, viewInflate);
                    if (writeModeResultsView != null) {
                        i = R.id.modesHeader;
                        View viewC = AbstractC3375o2.c(R.id.modesHeader, viewInflate);
                        if (viewC != null) {
                            int i2 = R.id.learn_progress_view;
                            ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.learn_progress_view, viewC);
                            if (progressBar != null) {
                                i2 = R.id.menu_modes_buttons;
                                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.menu_modes_buttons, viewC);
                                if (frameLayout2 != null) {
                                    i2 = R.id.menu_modes_star;
                                    if (((IconFontTextView) AbstractC3375o2.c(R.id.menu_modes_star, viewC)) != null) {
                                        i2 = R.id.menu_study_mode_settings;
                                        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.menu_study_mode_settings, viewC);
                                        if (imageView != null) {
                                            com.quizlet.features.infra.legacyadapter.databinding.f fVar = new com.quizlet.features.infra.legacyadapter.databinding.f((RelativeLayout) viewC, progressBar, frameLayout2, imageView, 5);
                                            i = R.id.studyModeAppBar;
                                            View viewC2 = AbstractC3375o2.c(R.id.studyModeAppBar, viewInflate);
                                            if (viewC2 != null) {
                                                return new C4608l((LinearLayout) viewInflate, frameLayout, writeModeCheckPointView, writeModePromptView, writeModeResultsView, fVar, com.onetrust.otpublishers.headless.databinding.b.a(viewC2));
                                            }
                                        }
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

    @Override // com.quizlet.features.write.base.b
    public final void P(Bundle bundle) {
        this.r = bundle.getBoolean("selectedOnlyBundle");
        String string = bundle.getString("studySessionId");
        this.q = string;
        this.I.b(string);
        this.g1 = bundle.getString("currentQuestionSessionId");
        long[] longArray = bundle.getLongArray("termsSortOrder");
        if (longArray != null) {
            this.L = longArray.length == 0 ? Collections.EMPTY_LIST : new com.google.common.primitives.a(longArray, 0, longArray.length);
        }
    }

    public final dagger.hilt.android.internal.managers.b R() {
        if (this.w1 == null) {
            synchronized (this.x1) {
                try {
                    if (this.w1 == null) {
                        this.w1 = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.w1;
    }

    public final void S() {
        EnumC4509p enumC4509p;
        r rVar;
        timber.log.c.a.a("continueRound: %d/%d", Integer.valueOf(this.f1), Integer.valueOf(this.V.size()));
        if (this.L == null) {
            DBSession dBSessionO = this.u.C;
            if (dBSessionO == null) {
                dBSessionO = O();
            }
            ArrayList terms = this.u.s;
            long timestamp = dBSessionO.getTimestamp();
            Intrinsics.checkNotNullParameter(terms, "terms");
            ArrayList arrayList = new ArrayList(C.q(terms, 10));
            Iterator it2 = terms.iterator();
            while (it2.hasNext()) {
                arrayList.add(Long.valueOf(((DBTerm) it2.next()).getId()));
            }
            this.L = A.d(arrayList, new Random(timestamp));
        }
        List allTermIdsSorted = this.L;
        if (allTermIdsSorted != null) {
            ArrayList roundTerms = this.V;
            Intrinsics.checkNotNullParameter(roundTerms, "roundTerms");
            Intrinsics.checkNotNullParameter(allTermIdsSorted, "allTermIdsSorted");
            ArrayList arrayList2 = new ArrayList(C.q(roundTerms, 10));
            Iterator it3 = roundTerms.iterator();
            while (it3.hasNext()) {
                arrayList2.add(Long.valueOf(((DBTerm) it3.next()).getId()));
            }
            ArrayList arrayList3 = new ArrayList(C.q(roundTerms, 10));
            Iterator it4 = roundTerms.iterator();
            while (it4.hasNext()) {
                DBTerm dBTerm = (DBTerm) it4.next();
                arrayList3.add(new Pair(Long.valueOf(dBTerm.getId()), dBTerm));
            }
            Pair[] pairArr = (Pair[]) arrayList3.toArray(new Pair[0]);
            this.V = q.k(q.f(q.h(q.e(CollectionsKt.D(allTermIdsSorted), new G(arrayList2, 24)), new G(V.g((Pair[]) Arrays.copyOf(pairArr, pairArr.length)), 25))));
        }
        boolean z = true;
        int i = this.f1 + 1;
        this.f1 = i;
        if (i < this.V.size()) {
            ((ProgressBar) ((C4608l) this.k).f.c).setVisibility(0);
            ((ProgressBar) ((C4608l) this.k).f.c).setMax(this.V.size());
            ((ProgressBar) ((C4608l) this.k).f.c).setProgress(this.f1);
            this.Y = (DBTerm) this.V.get(this.f1);
            ArrayList arrayList4 = this.V;
            for (DBTerm dBTerm2 : arrayList4.subList(this.f1, arrayList4.size())) {
                String url = dBTerm2.getDefinitionImageLargeUrl();
                if (org.apache.commons.lang3.e.d(url)) {
                    ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) this.m1).getClass();
                    com.bumptech.glide.m mRequestManager = Glide.c(this);
                    Intrinsics.checkNotNullParameter(mRequestManager, "mRequestManager");
                    Intrinsics.checkNotNullParameter(url, "url");
                    com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
                    Intrinsics.checkNotNullParameter(url, "url");
                    Intrinsics.checkNotNullParameter(ttl, "ttl");
                    com.quizlet.quizletandroid.ui.common.images.loading.offline.a aVar = new com.quizlet.quizletandroid.ui.common.images.loading.offline.a(url);
                    mRequestManager.getClass();
                    com.bumptech.glide.k kVarD = new com.bumptech.glide.k(mRequestManager.a, mRequestManager, Drawable.class, mRequestManager.b).D(aVar);
                    new com.bumptech.glide.request.f();
                    com.bumptech.glide.k kVarB = kVarD.B(new com.quizlet.quizletandroid.ui.common.images.loading.glide.b(new com.google.firebase.tracing.a(29, this, dBTerm2)));
                    kVarB.getClass();
                    kVarB.A(new com.bumptech.glide.request.target.c(kVarB.r), kVarB);
                }
            }
            DBTerm dBTerm3 = this.Y;
            this.V.size();
            U();
            V();
            if (((C4608l) this.k).d.getCurrentTerm() == null || ((C4608l) this.k).d.getCurrentTerm().getLocalId() != dBTerm3.getLocalId()) {
                d0();
            } else {
                z = false;
            }
            ((C4608l) this.k).d.f(this.t1.f(), dBTerm3);
            if (z) {
                this.g1 = UUID.randomUUID().toString();
                this.h1 = Long.valueOf(System.currentTimeMillis());
                X("view_start", dBTerm3, ((C4608l) this.k).d.getCurrentAnswerType());
            }
            ((C4608l) this.k).d.setVisibility(0);
            ((ProgressBar) ((C4608l) this.k).f.c).setVisibility(0);
            ((ImageView) ((C4608l) this.k).f.e).setVisibility(0);
            return;
        }
        this.M.removeAll(this.X);
        if (this.M.size() == 0 && this.W.size() == 0) {
            c0(this.Z, this.c1);
            return;
        }
        timber.log.c.a.a("Showing checkpoint: %d, %d, %d", Integer.valueOf(this.V.size()), Integer.valueOf(this.W.size()), Integer.valueOf(this.M.size()));
        ArrayList arrayList5 = this.X;
        ArrayList arrayList6 = this.W;
        HashMap map = this.c1;
        int i2 = this.d1;
        d0();
        ((ProgressBar) ((C4608l) this.k).f.c).setVisibility(8);
        ((ProgressBar) ((C4608l) this.k).f.c).setVisibility(0);
        this.i1.b(true);
        ((C4608l) this.k).d.c();
        ((C4608l) this.k).d.setVisibility(8);
        V();
        InputMethodManager inputMethodManager = (InputMethodManager) getSystemService("input_method");
        if (getCurrentFocus() != null) {
            inputMethodManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 1);
        }
        WriteModeCheckPointView writeModeCheckPointView = ((C4608l) this.k).c;
        C0219q c0219q = this.u.B;
        writeModeCheckPointView.l = arrayList5;
        writeModeCheckPointView.k = arrayList6;
        com.quizlet.quizletandroid.ui.common.adapter.b bVar = new com.quizlet.quizletandroid.ui.common.adapter.b(writeModeCheckPointView.b.getContext(), writeModeCheckPointView.a);
        writeModeCheckPointView.g = bVar;
        bVar.d = c0219q;
        bVar.clear();
        writeModeCheckPointView.g.addAll(writeModeCheckPointView.k);
        com.quizlet.quizletandroid.ui.common.adapter.b bVar2 = new com.quizlet.quizletandroid.ui.common.adapter.b(writeModeCheckPointView.b.getContext(), writeModeCheckPointView.a);
        writeModeCheckPointView.h = bVar2;
        bVar2.d = c0219q;
        bVar2.clear();
        writeModeCheckPointView.h.addAll(writeModeCheckPointView.l);
        int size = map.size();
        com.commonsware.cwac.merge.c cVar = new com.commonsware.cwac.merge.c();
        writeModeCheckPointView.m = cVar;
        cVar.b((LinearLayout) ((com.onetrust.otpublishers.headless.databinding.b) writeModeCheckPointView.i.b).b);
        if (!writeModeCheckPointView.g.isEmpty()) {
            int size2 = writeModeCheckPointView.k.size();
            View viewInflate = ((LayoutInflater) writeModeCheckPointView.getContext().getSystemService("layout_inflater")).inflate(R.layout.write_mode_results_section_header, (ViewGroup) null);
            TextView textView = (TextView) viewInflate.findViewById(R.id.write_mode_results_section_header_text);
            textView.setTextColor(com.quizlet.themes.extensions.a.a(writeModeCheckPointView.getContext(), R.attr.AssemblyErrorText));
            textView.setText(writeModeCheckPointView.getResources().getQuantityString(R.plurals.number_of_questions_incorrect, size2, Integer.valueOf(size2)));
            writeModeCheckPointView.m.b(viewInflate);
            writeModeCheckPointView.m.a(writeModeCheckPointView.g);
        }
        if (!writeModeCheckPointView.h.isEmpty()) {
            int size3 = writeModeCheckPointView.l.size();
            View viewInflate2 = ((LayoutInflater) writeModeCheckPointView.getContext().getSystemService("layout_inflater")).inflate(R.layout.write_mode_results_section_header, (ViewGroup) null);
            TextView textView2 = (TextView) viewInflate2.findViewById(R.id.write_mode_results_section_header_text);
            textView2.setTextColor(com.quizlet.themes.extensions.a.a(writeModeCheckPointView.getContext(), R.attr.textColorSuccess));
            textView2.setText(writeModeCheckPointView.getResources().getQuantityString(R.plurals.number_of_questions_correct, size3, Integer.valueOf(size3)));
            writeModeCheckPointView.m.b(viewInflate2);
            writeModeCheckPointView.m.a(writeModeCheckPointView.h);
        }
        writeModeCheckPointView.b.setAdapter((ListAdapter) writeModeCheckPointView.m);
        ProgressBar progressBar = (ProgressBar) ((com.onetrust.otpublishers.headless.databinding.b) writeModeCheckPointView.i.b).d;
        progressBar.setProgress(i2);
        progressBar.setMax(size);
        if (((C4608l) this.k).c.getVisibility() != 0) {
            StudyModeEventLogger studyModeEventLogger = this.t;
            String str = this.q;
            G1 g1 = this.p;
            Integer num = this.l;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = this.u;
            studyModeEventLogger.e(str, g1, num, aVar2 != null ? aVar2.C : null, this.m, this.o, Boolean.valueOf(this.r), "checkpoint", null);
            com.quizlet.data.repository.widget.b bVar3 = this.q1;
            long jLongValue = this.m.longValue();
            G1 studiableType = this.p;
            String studiableName = this.n;
            A1 studyMode = A1.WRITE;
            bVar3.getClass();
            Intrinsics.checkNotNullParameter(studiableType, "studiableType");
            Intrinsics.checkNotNullParameter(studiableName, "studiableName");
            Intrinsics.checkNotNullParameter(studyMode, "studyMode");
            Intrinsics.checkNotNullParameter("checkpoint", "studyStep");
            if (((UserInfoCache) bVar3.c).b()) {
                Intrinsics.checkNotNullParameter(studiableType, "<this>");
                int i3 = com.quizlet.quizletandroid.braze.events.a.a[studiableType.ordinal()];
                if (i3 == 1) {
                    enumC4509p = EnumC4509p.SET;
                } else if (i3 == 2) {
                    enumC4509p = EnumC4509p.FOLDER;
                } else {
                    if (i3 != 3) {
                        throw new NoWhenBranchMatchedException();
                    }
                    enumC4509p = EnumC4509p.PREP_PACK;
                }
                Intrinsics.checkNotNullParameter(studyMode, "<this>");
                switch (com.quizlet.quizletandroid.braze.events.a.b[studyMode.ordinal()]) {
                    case 1:
                        rVar = r.WRITE;
                        break;
                    case 2:
                        rVar = r.FLASHCARDS;
                        break;
                    case 3:
                        rVar = r.TEST;
                        break;
                    case 4:
                        rVar = r.SPACE_RACE;
                        break;
                    case 5:
                        rVar = r.SCATTER;
                        break;
                    case 6:
                        rVar = r.VOICE_RACE;
                        break;
                    case 7:
                        rVar = r.VOICE_SCATTER;
                        break;
                    case 8:
                        rVar = r.SPELLER;
                        break;
                    case 9:
                        rVar = r.BISMARCK;
                        break;
                    case 10:
                        rVar = r.MOBILE_CARDS;
                        break;
                    case 11:
                        rVar = r.MOBILE_WRITE;
                        break;
                    case 12:
                        rVar = r.MOBILE_SCATTER;
                        break;
                    case 13:
                        rVar = r.GRAVITY;
                        break;
                    case 14:
                        rVar = r.MICROSCATTER;
                        break;
                    case 15:
                        rVar = r.REVIEW;
                        break;
                    case 16:
                        rVar = r.MULTIPLAYER;
                        break;
                    case 17:
                        rVar = r.LEARNING_ASSISTANT;
                        break;
                    case 18:
                        rVar = r.LOCATE;
                        break;
                    case 19:
                        rVar = r.QCHAT;
                        break;
                    case 20:
                        rVar = r.GAMES_HUB;
                        break;
                    case 21:
                        rVar = r.BLOCKS;
                        break;
                    case EventType.WINDOW_STATE /* 22 */:
                        rVar = r.SINGLE_PLAYER_BLAST;
                        break;
                    case EventType.AUDIO /* 23 */:
                        rVar = r.FLIP;
                        break;
                    case EventType.VIDEO /* 24 */:
                        rVar = r.CHARMS;
                        break;
                    default:
                        throw new NoWhenBranchMatchedException();
                }
                r rVar2 = rVar;
                Intrinsics.checkNotNullParameter("checkpoint", "<this>");
                com.quizlet.quizletandroid.braze.events.c event = new com.quizlet.quizletandroid.braze.events.c(jLongValue, enumC4509p, studiableName, rVar2, EnumC4520t.CHECKPOINT);
                com.quizlet.data.interactor.course.a aVar3 = (com.quizlet.data.interactor.course.a) bVar3.b;
                Intrinsics.checkNotNullParameter(event, "event");
                ((Braze) aVar3.b).logCustomEvent("study_session", (BrazeProperties) event.b);
            }
            ((C4608l) this.k).c.setVisibility(0);
        }
    }

    public final void U() {
        if (((C4608l) this.k).c.getVisibility() != 8) {
            StudyModeEventLogger studyModeEventLogger = this.t;
            String str = this.q;
            G1 g1 = this.p;
            Integer num = this.l;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
            studyModeEventLogger.f(str, g1, num, aVar == null ? null : aVar.C, this.m, this.o, Boolean.valueOf(this.r), "checkpoint");
            ((C4608l) this.k).c.setVisibility(8);
        }
    }

    public final void V() {
        if (((C4608l) this.k).e.getVisibility() != 8) {
            StudyModeEventLogger studyModeEventLogger = this.t;
            String str = this.q;
            G1 g1 = this.p;
            Integer num = this.l;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
            studyModeEventLogger.f(str, g1, num, aVar == null ? null : aVar.C, this.m, this.o, Boolean.valueOf(this.r), "results");
            ((C4608l) this.k).e.setVisibility(8);
        }
    }

    public final void W(long j) {
        Integer num = (Integer) this.Z.get(Long.valueOf(j));
        this.Z.put(Long.valueOf(j), Integer.valueOf((num == null ? 0 : num.intValue()) + 1));
    }

    public final void X(String str, DBTerm dBTerm, Integer num) {
        com.features.flashcards.creatormarketing.h hVar = this.o1;
        String str2 = this.q;
        String str3 = this.g1;
        WriteStudyModeConfig writeStudyModeConfigF = this.t1.f();
        hVar.getClass();
        O1 o1 = O1.WORD;
        O1 o12 = writeStudyModeConfigF.a;
        O1 o13 = o12 == o1 ? O1.DEFINITION : o1;
        Long lValueOf = dBTerm.getId() < 0 ? null : Long.valueOf(dBTerm.getId());
        long localId = dBTerm.getLocalId();
        int iIntValue = num.intValue();
        boolean zD = org.apache.commons.lang3.e.d(dBTerm.getText(o12));
        boolean zB = com.features.flashcards.creatormarketing.h.b(dBTerm, o12);
        boolean zHasWordAudio = o12 == o1 ? dBTerm.hasWordAudio() : dBTerm.hasDefinitionAudio();
        boolean zD2 = org.apache.commons.lang3.e.d(dBTerm.getText(o13));
        boolean zB2 = com.features.flashcards.creatormarketing.h.b(dBTerm, o13);
        boolean zHasWordAudio2 = o13 == o1 ? dBTerm.hasWordAudio() : dBTerm.hasDefinitionAudio();
        A1 a1 = A1.MOBILE_WRITE;
        assistantMode.enums.k kVar = assistantMode.enums.k.b;
        QuestionEventLog.b.getClass();
        hVar.a.v(QuestionEventLog.Companion.a(str, str2, str3, lValueOf, localId, iIntValue, zD, zB, zHasWordAudio, zD2, zB2, zHasWordAudio2, null, o12, null, null, null, "", null, null, null, null, a1, kVar));
    }

    public final void Y(DBSession dBSession) {
        timber.log.c.a.a("completeRound", new Object[0]);
        this.V.clear();
        this.V.addAll(this.W);
        this.W.clear();
        this.X.clear();
        Collections.shuffle(this.M, new Random(dBSession.getTimestamp()));
        while (this.V.size() < 7 && this.M.size() > 0) {
            this.V.add((DBTerm) this.M.remove(0));
        }
        if (this.V.size() == 0) {
            c0(this.Z, this.c1);
            return;
        }
        this.e1++;
        this.f1 = -1;
        S();
    }

    public final void Z(Bundle bundle) {
        super.onCreate(bundle);
        v.a(this);
        LinearLayout linearLayout = ((C4608l) this.k).a;
        com.quizlet.quizletandroid.ui.setcreation.imageupload.a aVar = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(4);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        L.m(linearLayout, aVar);
        C4595c c4595c = this.n1;
        long jLongValue = this.m.longValue();
        G1 g1 = this.p;
        u uVar = c4595c.a.a;
        com.quizlet.billing.register.a aVarJ1 = uVar.j1();
        z zVarD1 = uVar.d1();
        Context context = uVar.q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.quizlet.quizletandroid.modes", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        androidx.work.impl.background.greedy.d dVar = new androidx.work.impl.background.greedy.d();
        dVar.a = jLongValue;
        dVar.b = g1;
        dVar.c = aVarJ1;
        dVar.d = zVarD1;
        dVar.e = sharedPreferences;
        this.t1 = dVar;
        if (bundle != null) {
            P(bundle);
        }
        int i = getResources().getDisplayMetrics().widthPixels;
        int i2 = getResources().getDisplayMetrics().heightPixels;
        double d = getResources().getDisplayMetrics().densityDpi;
        Math.sqrt(Math.pow(i2 / d, 2.0d) + Math.pow(i / d, 2.0d));
        ((C4608l) this.k).b.setLayoutTransition(new LayoutTransition());
        ((C4608l) this.k).c.setCheckPointListener(this);
        ((C4608l) this.k).e.setDelegate(this);
        ((C4608l) this.k).d.setTermPromptListener(this);
        ((C4608l) this.k).d.setImageOverlayListener(this);
        ((C4608l) this.k).d.setGrader(this.r1);
        ((C4608l) this.k).c.setVisibility(8);
        ((C4608l) this.k).e.setVisibility(8);
    }

    public final void a0() {
        Intent intentT = T(this, this.l, this.m, this.n, this.o, this.p, this.r);
        overridePendingTransition(0, 0);
        intentT.addFlags(65536);
        finish();
        overridePendingTransition(0, 0);
        startActivity(intentT);
    }

    public final void b0(DBSession dBSession, ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList(this.u.s);
        this.d1 = 0;
        Iterator it2 = arrayList.iterator();
        int round = 0;
        while (it2.hasNext()) {
            DBAnswer dBAnswer = (DBAnswer) it2.next();
            if (dBAnswer.getRound() > round) {
                round = dBAnswer.getRound();
            }
            if (com.bumptech.glide.b.c(dBAnswer.getCorrectness())) {
                this.d1++;
            } else {
                W(dBAnswer.getTermId());
            }
            arrayList2.remove(this.c1.get(Long.valueOf(dBAnswer.getTermId())));
        }
        this.M = arrayList2;
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            DBAnswer dBAnswer2 = (DBAnswer) it3.next();
            if (dBAnswer2.getRound() == round && ((DBTerm) this.c1.get(Long.valueOf(dBAnswer2.getTermId()))) != null) {
                arrayList3.add(dBAnswer2);
            }
        }
        timber.log.a aVar = timber.log.c.a;
        aVar.a("Resuming session", new Object[0]);
        aVar.a("answers.size(): %d", Integer.valueOf(arrayList.size()));
        aVar.a("remainingTerms.size(): %d", Integer.valueOf(this.M.size()));
        aVar.a("highestRound: %d", Integer.valueOf(round));
        aVar.a("highestRoundTerms.size(): %d", Integer.valueOf(arrayList3.size()));
        if (dBSession == null) {
            dBSession = O();
        }
        this.e1 = round;
        this.s1.g(new E(this, dBSession, arrayList3, 11));
    }

    public final void c0(HashMap map, HashMap map2) {
        int i;
        View viewInflate;
        d0();
        ((ProgressBar) ((C4608l) this.k).f.c).setVisibility(8);
        ((ImageView) ((C4608l) this.k).f.e).setVisibility(8);
        this.i1.b(true);
        ((C4608l) this.k).d.c();
        ((C4608l) this.k).d.setVisibility(8);
        U();
        InputMethodManager inputMethodManager = (InputMethodManager) getSystemService("input_method");
        if (getCurrentFocus() != null) {
            inputMethodManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(), 1);
        }
        int i2 = 0;
        if (((C4608l) this.k).e.getVisibility() != 0) {
            StudyModeEventLogger studyModeEventLogger = this.t;
            String str = this.q;
            G1 g1 = this.p;
            Integer num = this.l;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
            studyModeEventLogger.e(str, g1, num, aVar == null ? null : aVar.C, this.m, this.o, Boolean.valueOf(this.r), "results", null);
            this.u1 = Boolean.TRUE;
            ((C4608l) this.k).e.setVisibility(0);
        }
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = this.u;
        if (aVar2 != null) {
            WriteModeResultsView writeModeResultsView = ((C4608l) this.k).e;
            C0219q c0219q = aVar2.B;
            writeModeResultsView.l = map;
            writeModeResultsView.m = map2;
            writeModeResultsView.o = c0219q;
            C3919b c3919b = new C3919b(new com.google.common.base.g(map), com.google.common.collect.v.a);
            Set setKeySet = map.keySet();
            C3922e c3922e = com.google.common.collect.j.b;
            Object[] array = (setKeySet instanceof Collection ? setKeySet : AbstractC3525r4.d(setKeySet.iterator())).toArray();
            AbstractC3531s4.e(array.length, array);
            Arrays.sort(array, c3919b);
            writeModeResultsView.n = com.google.common.collect.j.k(array.length, array).o();
            com.commonsware.cwac.merge.c cVar = new com.commonsware.cwac.merge.c();
            writeModeResultsView.p = cVar;
            cVar.b((LinearLayout) writeModeResultsView.h.b);
            com.quizlet.quizletandroid.ui.common.adapter.b bVar = new com.quizlet.quizletandroid.ui.common.adapter.b(((ListView) writeModeResultsView.i.c).getContext(), writeModeResultsView.b);
            bVar.d = writeModeResultsView.o;
            int i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            int i4 = 0;
            RelativeLayout relativeLayout = null;
            while (true) {
                int size = writeModeResultsView.n.size();
                i = R.id.write_mode_results_section_header_star;
                if (i4 == size) {
                    if (bVar.d() && relativeLayout != null) {
                        ((QStarIconView) relativeLayout.findViewById(R.id.write_mode_results_section_header_star)).setSelected(true);
                    }
                    writeModeResultsView.p.a(bVar);
                    ((ListView) writeModeResultsView.i.c).setAdapter((ListAdapter) writeModeResultsView.p);
                    com.quizlet.data.repository.folderwithcreator.e eVar = writeModeResultsView.h;
                    WriteModeResultsView writeModeResultsView2 = (WriteModeResultsView) eVar.d;
                    int i5 = ((com.quizlet.features.write.base.b) writeModeResultsView2.g).r ? R.string.learn_start_over_with_all : R.string.learn_start_over_with_selected_terms;
                    com.quizlet.explanations.databinding.n nVar = (com.quizlet.explanations.databinding.n) eVar.c;
                    ((QButton) nVar.b).setText(i5);
                    HashMap map3 = writeModeResultsView2.l;
                    int size2 = map3.keySet().size();
                    Iterator it2 = map3.keySet().iterator();
                    while (it2.hasNext()) {
                        if (((Integer) map3.get((Long) it2.next())).intValue() == 0) {
                            i2++;
                        }
                    }
                    ((ArcProgressLayout) nVar.f).setScore((int) ((i2 * 100.0d) / size2));
                    QTextView qTextView = (QTextView) nVar.d;
                    if (i2 == size2) {
                        qTextView.setText(writeModeResultsView2.getResources().getString(R.string.study_mode_results_title_great_job));
                    } else {
                        qTextView.setText(writeModeResultsView2.getResources().getString(R.string.study_mode_results_title_keep_studying));
                    }
                    eVar.q();
                    return;
                }
                Integer num2 = (Integer) writeModeResultsView.l.get(writeModeResultsView.n.get(i4));
                int iIntValue = num2.intValue();
                if (iIntValue < i3) {
                    if (bVar.d() && relativeLayout != null) {
                        ((QStarIconView) relativeLayout.findViewById(R.id.write_mode_results_section_header_star)).setSelected(true);
                    }
                    writeModeResultsView.p.a(bVar);
                    bVar = new com.quizlet.quizletandroid.ui.common.adapter.b(((ListView) writeModeResultsView.i.c).getContext(), writeModeResultsView.b);
                    bVar.d = writeModeResultsView.o;
                    viewInflate = LayoutInflater.from(((RelativeLayout) writeModeResultsView.i.b).getContext()).inflate(R.layout.write_mode_results_section_header, (ViewGroup) null, false);
                    QStarIconView qStarIconView = (QStarIconView) AbstractC3375o2.c(R.id.write_mode_results_section_header_star, viewInflate);
                    if (qStarIconView == null) {
                        break;
                    }
                    i = R.id.write_mode_results_section_header_text;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.write_mode_results_section_header_text, viewInflate);
                    if (qTextView2 == null) {
                        break;
                    }
                    RelativeLayout relativeLayout2 = (RelativeLayout) viewInflate;
                    qStarIconView.setVisibility(0);
                    qStarIconView.setOnClickListener(new com.braze.ui.inappmessage.views.a(26, qStarIconView, bVar));
                    if (iIntValue != 0) {
                        qTextView2.setTextColor(com.quizlet.themes.extensions.a.a(writeModeResultsView.getContext(), R.attr.AssemblyErrorText));
                        qTextView2.setText(writeModeResultsView.getResources().getQuantityString(R.plurals.incorrect_number_of_times, iIntValue, num2));
                    } else {
                        qTextView2.setTextColor(com.quizlet.themes.extensions.a.a(writeModeResultsView.getContext(), R.attr.textColorSuccess));
                        qTextView2.setText(writeModeResultsView.getResources().getString(R.string.never_missed));
                    }
                    writeModeResultsView.p.b(relativeLayout2);
                    relativeLayout = relativeLayout2;
                    i3 = iIntValue;
                }
                DBTerm dBTerm = (DBTerm) writeModeResultsView.m.get(writeModeResultsView.n.get(i4));
                if (dBTerm == null) {
                    timber.log.c.a.g("null term", new Object[0]);
                } else {
                    bVar.add(dBTerm);
                }
                i4++;
            }
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return R().d();
    }

    public final void d0() {
        if (((C4608l) this.k).d.getCurrentTerm() == null || this.h1 == null) {
            return;
        }
        DBTerm currentTerm = ((C4608l) this.k).d.getCurrentTerm();
        Integer currentAnswerType = ((C4608l) this.k).d.getCurrentAnswerType();
        System.currentTimeMillis();
        this.h1.longValue();
        X("view_end", currentTerm, currentAnswerType);
        this.h1 = null;
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        timber.log.c.a.a("On activity result: %s", intent);
        if (i == 1 && i2 == -1) {
            WriteStudyModeConfig writeStudyModeConfig = (WriteStudyModeConfig) intent.getParcelableExtra("learnModeConfig");
            boolean booleanExtra = intent.getBooleanExtra("learnModeRestart", false);
            boolean z = this.r != writeStudyModeConfig.e;
            this.t1.i(writeStudyModeConfig);
            Q(writeStudyModeConfig.e);
            if (booleanExtra) {
                O();
                this.j1.c(Models.SESSION);
            }
            if (z || booleanExtra) {
                a0();
            }
        }
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        if (this.u1.booleanValue()) {
            setResult(115);
        }
        super.onBackPressed();
    }

    @Override // com.quizlet.features.write.base.b, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        Z(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = R().b();
            this.v1 = aVarB;
            if (aVarB.l()) {
                this.v1.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.v1;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        super.onPause();
        this.i1.b(true);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        v((Toolbar) ((C4608l) this.k).g.d);
        ((ImageView) ((C4608l) this.k).f.e).setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 19));
        com.bumptech.glide.c cVarR = r();
        if (cVarR != null) {
            cVarR.u(false);
            cVarR.s(true);
            cVarR.v(com.quizlet.themes.extensions.a.d(this, R.drawable.ic_sys_close_x, R.attr.colorControlNormal));
        }
    }

    @Override // com.quizlet.features.write.base.b, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putString("currentQuestionSessionId", this.g1);
        List list = this.L;
        if (list != null) {
            bundle.putLongArray("termsSortOrder", AbstractC3543u4.b(list));
        }
    }

    @Override // com.quizlet.features.write.base.b, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        DBSession dBSession;
        UUID uuid;
        super.onStart();
        StudyModeEventLogger studyModeEventLogger = this.t;
        String str = this.q;
        G1 g1 = this.p;
        Integer num = this.l;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
        if (aVar == null) {
            dBSession = null;
            uuid = null;
        } else {
            dBSession = aVar.C;
            uuid = null;
        }
        Long l = this.m;
        UUID uuid2 = uuid;
        Long l2 = this.o;
        UUID uuid3 = uuid2;
        boolean z = this.r;
        com.quizlet.features.infra.basestudy.manager.c cVarC = this.p1.c(l.longValue());
        if (cVarC != null) {
            uuid3 = cVarC.a;
        }
        studyModeEventLogger.c(str, g1, num, dBSession, l, l2, z, null, uuid3);
        if (((C4608l) this.k).d.getCurrentTerm() != null) {
            DBTerm currentTerm = ((C4608l) this.k).d.getCurrentTerm();
            this.h1 = Long.valueOf(System.currentTimeMillis());
            X("view_start", currentTerm, ((C4608l) this.k).d.getCurrentAnswerType());
        }
    }

    @Override // com.quizlet.features.write.base.b, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        if (isFinishing()) {
            U();
            V();
        }
        this.K.d();
        com.quizlet.data.interactor.school.e eVar = ((C4608l) this.k).d.C;
        eVar.a = 0L;
        ((Handler) eVar.b).removeCallbacksAndMessages(null);
        d0();
        StudyModeEventLogger studyModeEventLogger = this.t;
        String str = this.q;
        G1 g1 = this.p;
        Integer num = this.l;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
        studyModeEventLogger.d(str, g1, num, aVar != null ? aVar.C : null, this.m, this.o, this.r, null);
        super.onStop();
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.y1;
    }
}
