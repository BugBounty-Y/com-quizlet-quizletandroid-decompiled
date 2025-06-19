package com.quizlet.ads.ui.fragments;

import android.content.Intent;
import androidx.lifecycle.Z;
import androidx.navigation.U;
import com.comscore.streaming.EventType;
import com.quizlet.features.flashcards.C4232f;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.features.match.data.AbstractC4363t;
import com.quizlet.features.match.data.C4360p;
import com.quizlet.features.match.data.C4361q;
import com.quizlet.features.match.data.C4362s;
import com.quizlet.features.match.data.S;
import com.quizlet.features.match.data.r;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.features.notes.detail.composables.magicnotesdetail.G;
import com.quizlet.quizletandroid.ui.globalnav.composable.s;
import com.quizlet.quizletandroid.ui.startpage.nav2.a0;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.y;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsActivity;
import com.quizlet.search.composables.E;
import java.util.ArrayList;
import kotlin.InterfaceC4938g;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Z, InterfaceC4953l {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public c(U function) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                ((U) obj2).invoke(obj);
                return;
            case 1:
                ((U) obj2).invoke(obj);
                return;
            case 2:
                ((U) obj2).invoke(obj);
                return;
            case 3:
                ((U) obj2).invoke(obj);
                return;
            case 4:
                ((C4232f) obj2).invoke(obj);
                return;
            case 5:
                ((J) obj2).invoke(obj);
                return;
            case 6:
                ((G) obj2).invoke(obj);
                return;
            case 7:
                ((G) obj2).invoke(obj);
                return;
            case 8:
                ((G) obj2).invoke(obj);
                return;
            case 9:
                ((J) obj2).invoke(obj);
                return;
            case 10:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 11:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 12:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 13:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 14:
                ((s) obj2).invoke(obj);
                return;
            case 15:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 16:
                ((a0) obj2).invoke(obj);
                return;
            case 17:
                S p0 = (S) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                String str = MatchActivity.s;
                MatchActivity context = (MatchActivity) obj2;
                String str2 = MatchSettingsActivity.q;
                MatchSettingsData currentSettings = p0.a;
                ArrayList availableTermSides = p0.f;
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(currentSettings, "currentSettings");
                Intrinsics.checkNotNullParameter(availableTermSides, "availableTermSides");
                StudyEventLogData studyEventLogData = p0.e;
                Intrinsics.checkNotNullParameter(studyEventLogData, "studyEventLogData");
                Intent intent = new Intent(context, (Class<?>) MatchSettingsActivity.class);
                intent.putExtra("com.quizlet.quizletandroid.ui.studymodes.match.CurrentSettings", currentSettings);
                intent.putExtra("com.quizlet.quizletandroid.ui.studymodes.match.SelectedTermCount", p0.b);
                intent.putIntegerArrayListExtra("com.quizlet.quizletandroid.ui.studymodes.match.AvailableTermSides", new ArrayList<>(availableTermSides));
                intent.putExtra("com.quizlet.quizletandroid.ui.studymodes.match.IsMatchRunning", p0.d);
                intent.putExtra("com.quizlet.quizletandroid.ui.studymodes.match.StudyEventLogData", studyEventLogData);
                context.startActivityForResult(intent, 1);
                return;
            case 18:
                AbstractC4363t p02 = (AbstractC4363t) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                String str3 = MatchGameFragment.m;
                MatchGameFragment matchGameFragment = (MatchGameFragment) obj2;
                matchGameFragment.getClass();
                if (p02 instanceof C4362s) {
                    long j = ((C4362s) p02).a;
                    com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT = matchGameFragment.T();
                    gVarT.n.j(Long.valueOf(j));
                    return;
                }
                if (p02 instanceof r) {
                    r rVar = (r) p02;
                    long j2 = rVar.a;
                    com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT2 = matchGameFragment.T();
                    gVarT2.getClass();
                    gVarT2.o.j(new Pair(Long.valueOf(j2), Long.valueOf(rVar.b)));
                    return;
                }
                if (!(p02 instanceof C4361q)) {
                    if (!(p02 instanceof C4360p)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    matchGameFragment.T().p.j(Unit.a);
                    return;
                } else {
                    long j3 = ((C4361q) p02).a;
                    com.quizlet.quizletandroid.ui.studymodes.match.viewmodel.g gVarT3 = matchGameFragment.T();
                    gVarT3.q.j(Long.valueOf(j3));
                    return;
                }
            case 19:
                ((y) obj2).invoke(obj);
                return;
            case 20:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case 21:
                ((com.quizlet.quizletandroid.ui.common.ads.G) obj2).invoke(obj);
                return;
            case EventType.WINDOW_STATE /* 22 */:
                ((com.quizlet.quizletandroid.ui.usersettings.fragments.a) obj2).invoke(obj);
                return;
            case EventType.AUDIO /* 23 */:
                ((E) obj2).invoke(obj);
                return;
            case EventType.VIDEO /* 24 */:
                ((com.quizlet.viewmodel.livedata.a) obj2).invoke(obj);
                return;
            default:
                ((com.quizlet.quizletandroid.ui.subject.f) obj2).invoke(obj);
                return;
        }
    }

    public final boolean equals(Object obj) {
        switch (this.a) {
            case 0:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 1:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 2:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 3:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 4:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 5:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 6:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 7:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 8:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 9:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 10:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 11:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 12:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 13:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 14:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 15:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 16:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 17:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 18:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 19:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 20:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case 21:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case EventType.AUDIO /* 23 */:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            case EventType.VIDEO /* 24 */:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
            default:
                if ((obj instanceof Z) && (obj instanceof InterfaceC4953l)) {
                    break;
                }
                break;
        }
        return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        switch (this.a) {
            case 0:
                return (U) this.b;
            case 1:
                return (U) this.b;
            case 2:
                return (U) this.b;
            case 3:
                return (U) this.b;
            case 4:
                return (C4232f) this.b;
            case 5:
                return (J) this.b;
            case 6:
                return (G) this.b;
            case 7:
                return (G) this.b;
            case 8:
                return (G) this.b;
            case 9:
                return (J) this.b;
            case 10:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 11:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 12:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 13:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 14:
                return (s) this.b;
            case 15:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 16:
                return (a0) this.b;
            case 17:
                return new C4956o(1, 0, MatchActivity.class, (MatchActivity) this.b, "goToMatchSettings", "goToMatchSettings(Lcom/quizlet/features/match/data/MatchStartSettingsData;)V");
            case 18:
                return new C4956o(1, 0, MatchGameFragment.class, (MatchGameFragment) this.b, "handleGameEvents", "handleGameEvents(Lcom/quizlet/features/match/data/MatchGameEvent;)V");
            case 19:
                return (y) this.b;
            case 20:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case 21:
                return (com.quizlet.quizletandroid.ui.common.ads.G) this.b;
            case EventType.WINDOW_STATE /* 22 */:
                return (com.quizlet.quizletandroid.ui.usersettings.fragments.a) this.b;
            case EventType.AUDIO /* 23 */:
                return (E) this.b;
            case EventType.VIDEO /* 24 */:
                return (com.quizlet.viewmodel.livedata.a) this.b;
            default:
                return (com.quizlet.quizletandroid.ui.subject.f) this.b;
        }
    }

    public final int hashCode() {
        switch (this.a) {
        }
        return getFunctionDelegate().hashCode();
    }

    public c(U function, byte b) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(U function, char c) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(U function, int i) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(C4232f function) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(J function) {
        this.a = 5;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(J function, byte b) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(G function) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(G function, byte b) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(G function, char c) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, byte b) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, byte b, byte b2) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, byte b, boolean z) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, char c) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, int i) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.common.ads.G function, short s) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(s function) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(a0 function) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(y function) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.subject.f function) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.quizletandroid.ui.usersettings.fragments.a function) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(E function) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public c(com.quizlet.viewmodel.livedata.a function) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
