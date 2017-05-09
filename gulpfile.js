

require('source-map-support').install();

const clangFormat = require('clang-format');
const del = require('del');
const format = require('gulp-clang-format');
const gulp = require('gulp');
const merge = require('merge2');
const mocha = require('gulp-mocha');
const sourcemaps = require('gulp-sourcemaps');
const ts = require('gulp-typescript');
const tslint = require('gulp-tslint');

const jsOutDir = 'lib';
const typesOutDir = 'types';
const testOutDir = 'test-js';
const sources = ['src/**/*.ts'];
const tests = ['test/**/*.ts'];
const allFiles = ['*.js'].concat(sources, tests);

let exitOnError = true;
function onError() {
  if (exitOnError) {
    process.exit(1);
  }
}

gulp.task('test.check-format', () => {
  return gulp.src(allFiles)
      .pipe(format.checkFormat('file', clangFormat))
      .on('warning', onError);
});

gulp.task('format', () => {
  return gulp.src(allFiles, {base: '.'})
      .pipe(format.format('file', clangFormat))
      .pipe(gulp.dest('.'));
});

gulp.task('test.check-lint', () => {
  return gulp.src(allFiles)
      .pipe(tslint({formatter: 'verbose'}))
      .pipe(tslint.report())
      .on('warning', onError);
});

gulp.task('clean', () => {
  return del([jsOutDir, typesOutDir, testOutDir]);
});

gulp.task('compile', () => {
  const tsResult = gulp.src(sources)
                       .pipe(sourcemaps.init())
                       .pipe(ts.createProject('tsconfig.json')())
                       .on('error', onError);
  return merge([
    tsResult.dts.pipe(gulp.dest(typesOutDir)),
    tsResult.js
        .pipe(sourcemaps.write(
            '.', {includeContent: false, sourceRoot: '../src'}))
        .pipe(gulp.dest(jsOutDir)),
    tsResult.js.pipe(gulp.dest(jsOutDir))
  ]);
});

gulp.task('test.compile', ['compile'], () => {
  return gulp.src(tests, {base: '.'})
      .pipe(sourcemaps.init())
      .pipe(ts.createProject('tsconfig.json')())
      .on('error', onError)
      .pipe(sourcemaps.write('.', {includeContent: false, sourceRoot: '../test'}))
      .pipe(gulp.dest(`${testOutDir}/`));
});

gulp.task('test.unit', ['test.compile'], () => {
  return gulp.src([`${testOutDir}/**/*.js`]).pipe(mocha({verbose: true}));
});

gulp.task('watch', () => {
  exitOnError = false;
  gulp.start(['test.compile']);
  // TODO: also run unit tests in a non-fatal way
  return gulp.watch(allFiles, ['test.compile']);
});

gulp.task('test', ['test.unit', 'test.check-format', 'test.check-lint']);
gulp.task('default', ['compile']);