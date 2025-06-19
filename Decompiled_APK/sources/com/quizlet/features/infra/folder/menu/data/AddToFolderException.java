package com.quizlet.features.infra.folder.menu.data;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public abstract class AddToFolderException extends Exception {

    @Metadata
    public static final class Adding extends AddToFolderException {
        public final Throwable a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public Adding(Throwable e) {
            super(e);
            Intrinsics.checkNotNullParameter(e, "e");
            this.a = e;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Adding) && Intrinsics.b(this.a, ((Adding) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        @Override // java.lang.Throwable
        public final String toString() {
            return "Adding(e=" + this.a + ")";
        }
    }

    @Metadata
    public static final class Multi extends AddToFolderException {
        public final Throwable a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public Multi(Throwable e) {
            super(e);
            Intrinsics.checkNotNullParameter(e, "e");
            this.a = e;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Multi) && Intrinsics.b(this.a, ((Multi) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        @Override // java.lang.Throwable
        public final String toString() {
            return "Multi(e=" + this.a + ")";
        }
    }

    @Metadata
    public static final class Removing extends AddToFolderException {
        public final Throwable a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public Removing(Throwable e) {
            super(e);
            Intrinsics.checkNotNullParameter(e, "e");
            this.a = e;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Removing) && Intrinsics.b(this.a, ((Removing) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        @Override // java.lang.Throwable
        public final String toString() {
            return "Removing(e=" + this.a + ")";
        }
    }
}
