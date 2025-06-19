package com.quizlet.eventlogger.features.setpage;

import com.google.firebase.perf.b;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.generated.enums.A1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SetPagePerformanceLogger {
    private Trace clickToStartStudyModeTrace;

    @NotNull
    private final b firebasePerformance;
    private Trace loadSetDataTrace;
    private Trace loadTermDataTrace;
    private Trace renderDiagramTrace;
    private Trace renderSetHeaderTrace;
    private Trace renderSetPreviewTrace;
    private Trace renderSetProgressTrace;
    private Trace renderTermListTrace;

    public SetPagePerformanceLogger(@NotNull b firebasePerformance) {
        Intrinsics.checkNotNullParameter(firebasePerformance, "firebasePerformance");
        this.firebasePerformance = firebasePerformance;
        firebasePerformance.getClass();
        this.loadSetDataTrace = Trace.c("SetPage: load set data");
        firebasePerformance.getClass();
        this.loadTermDataTrace = Trace.c("SetPage: load term data");
        firebasePerformance.getClass();
        this.renderSetPreviewTrace = Trace.c("SetPage: render set preview");
        firebasePerformance.getClass();
        this.renderSetHeaderTrace = Trace.c("SetPage: render set header");
        firebasePerformance.getClass();
        this.renderTermListTrace = Trace.c("SetPage: render term list");
        firebasePerformance.getClass();
        this.renderDiagramTrace = Trace.c("SetPage: render diagram");
        firebasePerformance.getClass();
        this.renderSetProgressTrace = Trace.c("SetPage: render set progress");
        firebasePerformance.getClass();
        this.clickToStartStudyModeTrace = Trace.c("SetPage: click to start study mode");
    }

    public final void a() {
        this.loadSetDataTrace = null;
        this.loadTermDataTrace = null;
        this.renderSetPreviewTrace = null;
        this.renderSetHeaderTrace = null;
        this.renderSetProgressTrace = null;
        this.renderTermListTrace = null;
        this.renderDiagramTrace = null;
        this.clickToStartStudyModeTrace = null;
    }

    public final void b(boolean z) {
        Trace trace = this.renderDiagramTrace;
        if (trace != null) {
            trace.putAttribute("HasDiagram", String.valueOf(z));
        }
        Trace trace2 = this.renderDiagramTrace;
        if (trace2 != null) {
            trace2.stop();
        }
        this.renderDiagramTrace = null;
    }

    public final void c() {
        Trace trace = this.renderSetProgressTrace;
        if (trace != null) {
            trace.start();
        }
    }

    public final void d() {
        Trace trace = this.loadSetDataTrace;
        if (trace != null) {
            trace.stop();
        }
        this.loadSetDataTrace = null;
    }

    public final void e() {
        Trace trace = this.renderSetHeaderTrace;
        if (trace != null) {
            trace.stop();
        }
        this.renderSetHeaderTrace = null;
    }

    public final void f() {
        Trace trace = this.renderSetPreviewTrace;
        if (trace != null) {
            trace.stop();
        }
        this.renderSetPreviewTrace = null;
    }

    public final void g() {
        Trace trace = this.renderSetProgressTrace;
        if (trace != null) {
            trace.stop();
        }
        this.renderSetProgressTrace = null;
    }

    public final void h() {
        Trace trace = this.renderDiagramTrace;
        if (trace != null) {
            trace.start();
        }
    }

    public final void i() {
        Trace trace = this.renderSetHeaderTrace;
        if (trace != null) {
            trace.start();
        }
    }

    public final void j() {
        Trace trace = this.loadSetDataTrace;
        if (trace != null) {
            trace.start();
        }
        Trace trace2 = this.renderSetPreviewTrace;
        if (trace2 != null) {
            trace2.start();
        }
    }

    public final void k() {
        Trace trace = this.loadTermDataTrace;
        if (trace != null) {
            trace.start();
        }
        Trace trace2 = this.renderTermListTrace;
        if (trace2 != null) {
            trace2.start();
        }
    }

    public final void l(A1 studyModeType) {
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        if (this.clickToStartStudyModeTrace == null) {
            this.firebasePerformance.getClass();
            this.clickToStartStudyModeTrace = Trace.c("SetPage: click to start study mode");
        }
        Trace trace = this.clickToStartStudyModeTrace;
        if (trace != null) {
            trace.putAttribute("StudyModeType", studyModeType.name());
        }
        Trace trace2 = this.clickToStartStudyModeTrace;
        if (trace2 != null) {
            trace2.start();
        }
    }

    public final void m() {
        Trace trace = this.clickToStartStudyModeTrace;
        if (trace != null) {
            trace.stop();
        }
        this.clickToStartStudyModeTrace = null;
    }

    public final void n() {
        Trace trace = this.loadTermDataTrace;
        if (trace != null) {
            trace.stop();
        }
        this.loadTermDataTrace = null;
    }

    public final void o() {
        Trace trace = this.renderTermListTrace;
        if (trace != null) {
            trace.stop();
        }
        this.renderTermListTrace = null;
    }
}
