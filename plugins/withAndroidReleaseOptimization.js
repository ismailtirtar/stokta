const {
  AndroidConfig,
  createRunOncePlugin,
  withGradleProperties,
} = require('expo/config-plugins');

const PLUGIN_NAME = 'with-android-release-optimization';
const PLUGIN_VERSION = '1.0.0';

function withAndroidReleaseOptimization(config) {
  return withGradleProperties(config, (gradleConfig) => {
    const { updateAndroidBuildProperty } = AndroidConfig.BuildProperties;

    updateAndroidBuildProperty(
      gradleConfig.modResults,
      'android.enableMinifyInReleaseBuilds',
      'true'
    );
    updateAndroidBuildProperty(
      gradleConfig.modResults,
      'android.enableShrinkResourcesInReleaseBuilds',
      'true'
    );

    return gradleConfig;
  });
}

module.exports = createRunOncePlugin(
  withAndroidReleaseOptimization,
  PLUGIN_NAME,
  PLUGIN_VERSION
);
