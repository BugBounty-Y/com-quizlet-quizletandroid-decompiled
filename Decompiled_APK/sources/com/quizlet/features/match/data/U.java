package com.quizlet.features.match.data;

import assistantMode.refactored.types.StudiableData;
import com.quizlet.features.match.settings.MatchSettingsData;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class U {
    public final ArrayList a;
    public final List b;
    public final List c;
    public final MatchSettingsData d;
    public final StudiableData e;
    public final assistantMode.enums.m f;
    public final assistantMode.enums.m g;

    public U(ArrayList termList, List diagramShapes, List imageRefs, MatchSettingsData settings) {
        Intrinsics.checkNotNullParameter(termList, "termList");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        Intrinsics.checkNotNullParameter(imageRefs, "imageRefs");
        Intrinsics.checkNotNullParameter(settings, "settings");
        this.a = termList;
        this.b = diagramShapes;
        this.c = imageRefs;
        this.d = settings;
        this.e = com.quizlet.features.infra.basestudy.utils.c.a.a(termList, diagramShapes, kotlin.collections.V.c());
        if (!settings.d || diagramShapes.isEmpty() || imageRefs.isEmpty()) {
            this.f = assistantMode.enums.m.c;
            this.g = assistantMode.enums.m.b;
        } else {
            this.f = assistantMode.enums.m.d;
            this.g = settings.c ? assistantMode.enums.m.c : assistantMode.enums.m.b;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U)) {
            return false;
        }
        U u = (U) obj;
        return Intrinsics.b(this.a, u.a) && Intrinsics.b(this.b, u.b) && Intrinsics.b(this.c, u.c) && this.d.equals(u.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + androidx.compose.animation.d0.f(androidx.compose.animation.d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        return "MatchStudyModeData(termList=" + this.a + ", diagramShapes=" + this.b + ", imageRefs=" + this.c + ", settings=" + this.d + ")";
    }
}
