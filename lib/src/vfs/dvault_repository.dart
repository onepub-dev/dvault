// Platform-aware export for DVaultRepository
// This file conditionally exports the appropriate implementation based on the platform

export 'io_repository.dart';

// When web support is added, this will become:
// export 'io_repository.dart' if (dart.library.html) 'web_repository_stub.dart';
